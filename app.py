import os
import io
import re
import secrets
from functools import wraps

import qrcode
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort,
    send_file, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, Cafe, CafeMember, CafeSettings, LoyaltyCard


# ---------------------------
# Utilities
# ---------------------------
def slugify(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "cafe"


def ensure_cafe_settings(cafe: Cafe) -> CafeSettings:
    if cafe.settings:
        return cafe.settings
    settings = CafeSettings(cafe_id=cafe.id)
    db.session.add(settings)
    db.session.commit()
    return settings


def ensure_loyalty_card(user: User, cafe: Cafe) -> LoyaltyCard:
    card = LoyaltyCard.query.filter_by(user_id=user.id, cafe_id=cafe.id).first()
    if card:
        return card
    card = LoyaltyCard(user_id=user.id, cafe_id=cafe.id)
    db.session.add(card)
    db.session.commit()
    return card


# ---------------------------
# App factory
# ---------------------------
def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        "sqlite:///coffee_loyalty_multi.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # app.config["SESSION_COOKIE_SECURE"] = True  # enable if HTTPS

    db.init_app(app)

    with app.app_context():
        db.create_all()
        seed_global_admin()

    # ---------------------------
    # Session / auth helpers
    # ---------------------------
    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        return db.session.get(User, uid)

    def current_cafe():
        cid = session.get("cafe_id")
        if not cid:
            return None
        cafe = db.session.get(Cafe, cid)
        if cafe and cafe.is_active:
            return cafe
        return None

    def is_global_admin(u: User) -> bool:
        return bool(u and u.is_global_admin and u.is_active)

    def get_membership(u: User, cafe: Cafe) -> CafeMember | None:
        if not u or not cafe:
            return None
        return CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()

    def require_login(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u or not u.is_active:
                session.clear()
                flash("Please log in.", "warning")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def require_cafe_selected(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_cafe():
                return redirect(url_for("select_cafe"))
            return fn(*args, **kwargs)
        return wrapper

    def require_global_admin(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not is_global_admin(u):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper

    def require_role_in_cafe(*roles):
        """
        roles: "manager", "staff"
        Global admin always allowed.
        """
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                u = current_user()
                if not u or not u.is_active:
                    return redirect(url_for("login"))

                cafe = current_cafe()
                if not cafe:
                    return redirect(url_for("select_cafe"))

                if is_global_admin(u):
                    return fn(*args, **kwargs)

                m = get_membership(u, cafe)
                if not m or m.role not in roles:
                    abort(403)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # ---------------------------
    # CSRF helpers
    # ---------------------------
    def get_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    def require_csrf():
        token_form = request.form.get("csrf_token", "")
        token_session = session.get("csrf_token", "")
        if not token_form or not token_session or token_form != token_session:
            abort(400, description="CSRF token missing/invalid")

    @app.context_processor
    def inject_globals():
        u = current_user()
        cafe = current_cafe()
        membership = None
        if u and cafe and not is_global_admin(u):
            membership = get_membership(u, cafe)
        return {
            "csrf_token": get_csrf_token(),
            "me": u,
            "active_cafe": cafe,
            "me_membership": membership,
            "me_is_admin": is_global_admin(u),
        }

    @app.errorhandler(400)
    def handle_400(err):
        session.pop("csrf_token", None)
        flash("Session expired — please try again.", "warning")
        return redirect(request.referrer or url_for("login"))

    # ---------------------------
    # Public routes
    # ---------------------------
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        # You can keep this public for customer accounts (platform-level),
        # then they join cafes later (manager adds them / or self-join later).
        if request.method == "POST":
            require_csrf()

            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""

            if not username or not email or not password:
                flash("Please fill in all fields.", "danger")
                return redirect(url_for("register"))
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return redirect(url_for("register"))

            if User.query.filter_by(username=username).first():
                flash("That username is already taken.", "danger")
                return redirect(url_for("register"))
            if User.query.filter_by(email=email).first():
                flash("That email is already registered.", "danger")
                return redirect(url_for("register"))

            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                is_active=True,
                is_global_admin=False,
            )
            db.session.add(user)
            db.session.commit()

            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            require_csrf()

            identifier = (request.form.get("identifier") or "").strip()
            password = request.form.get("password") or ""

            user = User.query.filter(
                (User.username == identifier) | (User.email == identifier.lower())
            ).first()

            if not user or not user.is_active or not check_password_hash(user.password_hash, password):
                flash("Invalid login.", "danger")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user.id
            session["csrf_token"] = secrets.token_urlsafe(32)

            flash("Login successful.", "success")
            return redirect(url_for("select_cafe"))

        return render_template("login.html")

    @app.post("/logout")
    def logout():
        require_csrf()
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("index"))

    # ---------------------------
    # Cafe selection / switching
    # ---------------------------
    @app.get("/select-cafe")
    @require_login
    def select_cafe():
        u = current_user()

        if is_global_admin(u):
            cafes = Cafe.query.filter_by(is_active=True).order_by(Cafe.name.asc()).all()
        else:
            cafes = (
                Cafe.query.join(CafeMember, Cafe.id == CafeMember.cafe_id)
                .filter(CafeMember.user_id == u.id, CafeMember.is_active == True)  # noqa: E712
                .filter(Cafe.is_active == True)  # noqa: E712
                .order_by(Cafe.name.asc())
                .all()
            )

        return render_template("select_cafe.html", cafes=cafes)

    @app.post("/select-cafe")
    @require_login
    def select_cafe_post():
        require_csrf()
        u = current_user()

        cafe_id = request.form.get("cafe_id")
        if not cafe_id or not cafe_id.isdigit():
            flash("Choose a cafe.", "danger")
            return redirect(url_for("select_cafe"))

        cafe = db.session.get(Cafe, int(cafe_id))
        if not cafe or not cafe.is_active:
            flash("Cafe not found.", "danger")
            return redirect(url_for("select_cafe"))

        if not is_global_admin(u):
            m = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            if not m:
                flash("You don't have access to that cafe.", "danger")
                return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id

        # Redirect by role within cafe
        if is_global_admin(u):
            return redirect(url_for("staff_home"))

        m = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
        if m and m.role in ("staff", "manager"):
            return redirect(url_for("staff_home"))

        # Otherwise treat as customer at that cafe
        return redirect(url_for("card"))

    @app.post("/switch-cafe")
    @require_login
    def switch_cafe():
        # Simple convenience: same as select-cafe POST
        return select_cafe_post()

    # ---------------------------
    # Customer card (per cafe)
    # ---------------------------
    @app.get("/card")
    @require_login
    @require_cafe_selected
    def card():
        u = current_user()
        cafe = current_cafe()

        # Customers can have cards even without membership;
        # you can later decide how a customer joins a cafe.
        settings = ensure_cafe_settings(cafe)
        card = ensure_loyalty_card(u, cafe)

        return render_template("card.html", card=card, settings=settings)

    # ---------------------------
    # QR image (token is per user)
    # ---------------------------
    @app.get("/qr/<token>")
    @require_login
    def qr_image(token):
        u = current_user()

        # allow global admin to view any QR
        if not is_global_admin(u) and u.qr_token != token:
            abort(403)

        img = qrcode.make(token)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")

    # ---------------------------
    # Staff scanner + prompt (per cafe)
    # ---------------------------
    @app.get("/staff")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_home():
        cafe = current_cafe()
        settings = ensure_cafe_settings(cafe)
        return render_template("staff.html", settings=settings)

    @app.get("/staff/lookup")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_lookup():
        cafe = current_cafe()
        token = (request.args.get("token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "Missing token"}), 400

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            return jsonify({"ok": False, "error": "User not found"}), 404

        settings = ensure_cafe_settings(cafe)
        card = ensure_loyalty_card(u, cafe)

        return jsonify({
            "ok": True,
            "user": {
                "id": u.id,
                "username": u.username,
                "email": u.email,
            },
            "card": {
                "stamps": card.stamp_count,
                "reward_available": bool(card.reward_available),
                "stamps_required": settings.stamps_required,
                "reward_name": settings.reward_name,
            }
        })

    @app.post("/staff/add-stamp-by-token")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_add_stamp_by_token():
        require_csrf()
        cafe = current_cafe()
        token = (request.form.get("token") or "").strip()
        if not token:
            flash("No token provided.", "danger")
            return redirect(url_for("staff_home"))

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            flash("User not found.", "danger")
            return redirect(url_for("staff_home"))

        settings = ensure_cafe_settings(cafe)
        card = ensure_loyalty_card(u, cafe)

        if card.reward_available:
            flash("Reward already available — redeem first.", "warning")
            return redirect(url_for("staff_home"))

        # increment stamp
        if card.stamp_count < settings.stamps_required:
            card.stamp_count += 1
            if card.stamp_count >= settings.stamps_required:
                card.stamp_count = settings.stamps_required
                card.reward_available = True

        db.session.commit()
        flash(f"Stamp added to {u.username}.", "success")
        return redirect(url_for("staff_home"))

    @app.post("/staff/redeem-by-token")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_redeem_by_token():
        require_csrf()
        cafe = current_cafe()
        token = (request.form.get("token") or "").strip()
        if not token:
            flash("No token provided.", "danger")
            return redirect(url_for("staff_home"))

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            flash("User not found.", "danger")
            return redirect(url_for("staff_home"))

        settings = ensure_cafe_settings(cafe)
        card = ensure_loyalty_card(u, cafe)

        # check permission (from settings)
        me = current_user()
        membership = CafeMember.query.filter_by(user_id=me.id, cafe_id=cafe.id, is_active=True).first()
        # managers can always redeem; staff depends on setting
        if membership and membership.role == "staff" and not settings.staff_can_redeem:
            flash("Staff are not allowed to redeem at this cafe.", "danger")
            return redirect(url_for("staff_home"))

        if not card.reward_available:
            flash("No reward available yet.", "warning")
            return redirect(url_for("staff_home"))

        card.stamp_count = 0
        card.reward_available = False
        db.session.commit()

        flash(f"Redeemed {settings.reward_name} for {u.username}.", "success")
        return redirect(url_for("staff_home"))

    @app.get("/staff/search-json")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_search_json():
        cafe = current_cafe()
        q = (request.args.get("q") or "").strip()

        if len(q) < 2:
            return jsonify([])

        settings = ensure_cafe_settings(cafe)

        users = (
            User.query.filter(User.is_active == True)  # noqa: E712
            .filter((User.username.ilike(f"{q}%")) | (User.email.ilike(f"{q}%")))
            .order_by(User.username.asc())
            .limit(10)
            .all()
        )

        payload = []
        for u in users:
            card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not card:
                # don’t auto-create for search; just show 0
                stamps = 0
                reward = False
            else:
                stamps = card.stamp_count
                reward = bool(card.reward_available)

            payload.append({
                "username": u.username,
                "email": u.email,
                "stamps": stamps,
                "reward_available": reward,
                "stamps_required": settings.stamps_required,
                "reward_name": settings.reward_name,
                "qr_token": u.qr_token,
            })

        return jsonify(payload)

    # ---------------------------
    # Manager dashboard (per cafe)
    # ---------------------------
    @app.get("/manager")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_dashboard():
        cafe = current_cafe()

        # Customers at this cafe = anyone with a loyalty card for this cafe
        cards = (
            LoyaltyCard.query.filter_by(cafe_id=cafe.id)
            .order_by(LoyaltyCard.updated_at.desc())
            .limit(300)
            .all()
        )

        # list of (User, LoyaltyCard)
        rows = []
        for c in cards:
            u = db.session.get(User, c.user_id)
            if not u:
                continue
            # managers should NOT see global admins
            if u.is_global_admin:
                continue
            rows.append((u, c))

        settings = ensure_cafe_settings(cafe)
        return render_template("manager_dashboard.html", rows=rows, settings=settings)

    @app.post("/manager/reset-loyalty")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_reset_loyalty():
        require_csrf()
        cafe = current_cafe()

        user_id = request.form.get("user_id")
        if not user_id or not user_id.isdigit():
            flash("Invalid user.", "danger")
            return redirect(url_for("manager_dashboard"))

        u = db.session.get(User, int(user_id))
        if not u or u.is_global_admin:
            flash("User not found.", "danger")
            return redirect(url_for("manager_dashboard"))

        card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
        if not card:
            flash("No loyalty card for this user at this cafe.", "warning")
            return redirect(url_for("manager_dashboard"))

        card.stamp_count = 0
        card.reward_available = False
        db.session.commit()

        flash(f"Reset loyalty for {u.username}.", "success")
        return redirect(url_for("manager_dashboard"))

    # ---------------------------
    # Cafe settings (manager/admin)
    # ---------------------------
    @app.get("/settings")
    @require_login
    @require_cafe_selected
    def cafe_settings():
        u = current_user()
        cafe = current_cafe()

        # allowed: global admin OR manager at this cafe
        if not is_global_admin(u):
            m = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            if not m or m.role != "manager":
                abort(403)

        settings = ensure_cafe_settings(cafe)
        return render_template("cafe_settings.html", settings=settings)

    @app.post("/settings")
    @require_login
    @require_cafe_selected
    def cafe_settings_post():
        require_csrf()
        u = current_user()
        cafe = current_cafe()

        if not is_global_admin(u):
            m = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            if not m or m.role != "manager":
                abort(403)

        settings = ensure_cafe_settings(cafe)

        stamps_required = request.form.get("stamps_required", "").strip()
        reward_name = (request.form.get("reward_name") or "").strip()
        staff_can_redeem = request.form.get("staff_can_redeem") == "on"

        if not stamps_required.isdigit():
            flash("Stamps required must be a number.", "danger")
            return redirect(url_for("cafe_settings"))

        stamps_required_i = int(stamps_required)
        if stamps_required_i < 1 or stamps_required_i > 50:
            flash("Stamps required must be between 1 and 50.", "danger")
            return redirect(url_for("cafe_settings"))

        if not reward_name:
            flash("Reward name is required.", "danger")
            return redirect(url_for("cafe_settings"))

        settings.stamps_required = stamps_required_i
        settings.reward_name = reward_name
        settings.staff_can_redeem = staff_can_redeem
        db.session.commit()

        flash("Settings updated.", "success")
        return redirect(url_for("cafe_settings"))

    # ---------------------------
    # Admin-only: create cafe + assign manager
    # ---------------------------
    @app.get("/admin/create-cafe")
    @require_login
    @require_global_admin
    def admin_create_cafe():
        return render_template("admin_create_cafe.html")

    @app.post("/admin/create-cafe")
    @require_login
    @require_global_admin
    def admin_create_cafe_post():
        require_csrf()

        cafe_name = (request.form.get("cafe_name") or "").strip()
        slug = (request.form.get("slug") or "").strip().lower()
        manager_email = (request.form.get("manager_email") or "").strip().lower()
        manager_username = (request.form.get("manager_username") or "").strip()
        manager_password = request.form.get("manager_password") or ""

        if not cafe_name:
            flash("Cafe name required.", "danger")
            return redirect(url_for("admin_create_cafe"))

        if not slug:
            slug = slugify(cafe_name)
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
            flash("Slug must be lowercase letters/numbers with hyphens.", "danger")
            return redirect(url_for("admin_create_cafe"))

        if Cafe.query.filter_by(slug=slug).first():
            flash("Slug already used.", "danger")
            return redirect(url_for("admin_create_cafe"))

        cafe = Cafe(name=cafe_name, slug=slug, is_active=True)
        db.session.add(cafe)
        db.session.flush()

        settings = CafeSettings(cafe_id=cafe.id)
        db.session.add(settings)

        # Optional: create/assign manager membership
        manager_user = None
        if manager_email:
            manager_user = User.query.filter_by(email=manager_email).first()
            if not manager_user:
                # Create new manager user requires username + password
                if not manager_username or len(manager_password) < 8:
                    flash("To create a new manager, provide username and 8+ char password.", "danger")
                    db.session.rollback()
                    return redirect(url_for("admin_create_cafe"))

                if User.query.filter_by(username=manager_username).first():
                    flash("Manager username already taken.", "danger")
                    db.session.rollback()
                    return redirect(url_for("admin_create_cafe"))

                manager_user = User(
                    username=manager_username,
                    email=manager_email,
                    password_hash=generate_password_hash(manager_password),
                    is_active=True,
                    is_global_admin=False,
                )
                db.session.add(manager_user)
                db.session.flush()

            # Assign membership as manager
            existing = CafeMember.query.filter_by(user_id=manager_user.id, cafe_id=cafe.id).first()
            if not existing:
                db.session.add(CafeMember(user_id=manager_user.id, cafe_id=cafe.id, role="manager", is_active=True))

        db.session.commit()

        flash(f"Created cafe '{cafe.name}' (/{cafe.slug}).", "success")
        return redirect(url_for("select_cafe"))

    return app


# ---------------------------
# Seed global admin
# ---------------------------
def seed_global_admin():
    """
    Creates a single global admin if none exists.
    Login:
      username: admin
      password: ChangeMe123!
    """
    if User.query.filter_by(is_global_admin=True).first():
        return

    admin = User(
        username="admin",
        email="admin@local",
        password_hash=generate_password_hash("ChangeMe123!"),
        is_active=True,
        is_global_admin=True,
    )
    db.session.add(admin)
    db.session.commit()


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)
