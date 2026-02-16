import os
import io
import secrets
from functools import wraps

import qrcode
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort,
    send_file, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, LoyaltyCard


def seed_admin():
    """Create a default admin if none exists (dev convenience)."""
    if User.query.filter_by(role="admin").first():
        return

    admin = User(
        username="admin",
        email="admin@local",
        password_hash=generate_password_hash("ChangeMe123!"),
        role="admin",
        is_active=True,
    )
    db.session.add(admin)
    db.session.flush()
    db.session.add(LoyaltyCard(user_id=admin.id))
    db.session.commit()


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # NEW DB filename to avoid schema headaches during dev
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///coffee_loyalty_v4.db"

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # app.config["SESSION_COOKIE_SECURE"] = True  # enable on HTTPS

    db.init_app(app)

    with app.app_context():
        db.create_all()
        seed_admin()

    # ---------------------------
    # Helpers
    # ---------------------------
    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        u = db.session.get(User, uid)
        return u

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))

            u = db.session.get(User, uid)
            if not u or not u.is_active:
                session.clear()
                flash("Account inactive or session invalid. Please log in again.", "warning")
                return redirect(url_for("login"))

            return fn(*args, **kwargs)
        return wrapper

    def role_required(*roles):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                uid = session.get("user_id")
                if not uid:
                    return redirect(url_for("login"))
                u = db.session.get(User, uid)
                if not u or not u.is_active or u.role not in roles:
                    abort(403)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

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
        return {"csrf_token": get_csrf_token(), "me": current_user()}

    @app.errorhandler(400)
    def handle_400(err):
        session.pop("csrf_token", None)
        flash("Session expired — please try again.", "warning")
        return redirect(request.referrer or url_for("login"))

    # ---------------------------
    # Routes: public
    # ---------------------------
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
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
                role="customer",
                is_active=True,
            )
            db.session.add(user)
            db.session.flush()
            db.session.add(LoyaltyCard(user_id=user.id))
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
                flash("Invalid login details (or account inactive).", "danger")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user.id
            session["csrf_token"] = secrets.token_urlsafe(32)

            flash("Login successful.", "success")

            if user.role in ("staff", "admin"):
                return redirect(url_for("staff_home"))
            return redirect(url_for("card"))

        return render_template("login.html")

    @app.post("/logout")
    def logout():
        require_csrf()
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("index"))

    # ---------------------------
    # Customer: card
    # ---------------------------
    @app.get("/card")
    @login_required
    def card():
        user = db.session.get(User, session["user_id"])

        if not user.loyalty_card:
            db.session.add(LoyaltyCard(user_id=user.id))
            db.session.commit()

        return render_template("card.html", card=user.loyalty_card)

    @app.post("/card/add-stamp")
    @login_required
    def add_stamp_demo():
        require_csrf()
        user = db.session.get(User, session["user_id"])
        card = user.loyalty_card

        if card.reward_available:
            flash("Reward already available — redeem it first.", "warning")
            return redirect(url_for("card"))

        if card.stamp_count < 9:
            card.stamp_count += 1
            if card.stamp_count >= 9:
                card.stamp_count = 9
                card.reward_available = True

        db.session.commit()
        flash("Stamp added (demo).", "success")
        return redirect(url_for("card"))

    @app.post("/card/redeem")
    @login_required
    def redeem():
        require_csrf()
        user = db.session.get(User, session["user_id"])
        card = user.loyalty_card

        if not card.reward_available:
            flash("No reward available yet.", "danger")
            return redirect(url_for("card"))

        card.stamp_count = 0
        card.reward_available = False
        db.session.commit()

        flash("Reward redeemed!", "success")
        return redirect(url_for("card"))

    # ---------------------------
    # QR
    # ---------------------------
    @app.get("/qr/<token>")
    @login_required
    def qr_image(token):
        me = db.session.get(User, session["user_id"])
        if me.role not in ("staff", "admin") and me.qr_token != token:
            abort(403)

        img = qrcode.make(token)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")

    # ---------------------------
    # Staff: scanner + improved live search
    # ---------------------------
    @app.get("/staff")
    @role_required("staff", "admin")
    def staff_home():
        return render_template("staff.html")

    @app.get("/staff/search-json")
    @role_required("staff", "admin")
    def staff_search_json():
        q = (request.args.get("q") or "").strip()

        # prevents "show everything"
        if len(q) < 2:
            return jsonify([])

        results = (
            User.query.filter(User.is_active == True)  # noqa: E712
            .filter(
                (User.username.ilike(f"{q}%")) | (User.email.ilike(f"{q}%"))
            )
            .order_by(User.username.asc())
            .limit(10)
            .all()
        )

        payload = []
        for u in results:
            stamps = u.loyalty_card.stamp_count if u.loyalty_card else 0
            reward = bool(u.loyalty_card.reward_available) if u.loyalty_card else False
            payload.append({
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "stamps": stamps,
                "reward_available": reward,
                "qr_token": u.qr_token
            })

        return jsonify(payload)

    @app.post("/staff/add-stamp-by-token")
    @role_required("staff", "admin")
    def staff_add_stamp_by_token():
        require_csrf()
        token = (request.form.get("token") or "").strip()

        user = User.query.filter_by(qr_token=token).first()
        if not user or not user.is_active:
            flash("User not found or inactive.", "danger")
            return redirect(url_for("staff_home"))

        if not user.loyalty_card:
            db.session.add(LoyaltyCard(user_id=user.id))
            db.session.commit()

        card = user.loyalty_card

        if card.reward_available:
            flash("Reward already available — redeem first.", "warning")
            return redirect(url_for("staff_home"))

        if card.stamp_count < 9:
            card.stamp_count += 1
            if card.stamp_count >= 9:
                card.stamp_count = 9
                card.reward_available = True

        db.session.commit()
        flash(f"Stamp added to {user.username}.", "success")
        return redirect(url_for("staff_home"))

    # ---------------------------
    # Admin: user list + manage
    # ---------------------------
    @app.get("/admin/users")
    @role_required("admin")
    def admin_users():
        q = (request.args.get("q") or "").strip()
        role = (request.args.get("role") or "").strip()  # optional filter

        query = User.query

        if q:
            query = query.filter(
                (User.username.ilike(f"%{q}%")) | (User.email.ilike(f"%{q}%"))
            )
        if role in ("customer", "staff", "admin"):
            query = query.filter(User.role == role)

        users = query.order_by(User.created_at.desc()).limit(200).all()
        return render_template("admin_users.html", users=users, q=q, role=role)

    @app.get("/admin/users/<int:user_id>")
    @role_required("admin")
    def admin_user_view(user_id: int):
        u = db.session.get(User, user_id)
        if not u:
            abort(404)
        if not u.loyalty_card:
            db.session.add(LoyaltyCard(user_id=u.id))
            db.session.commit()
        return render_template("admin_user.html", u=u, card=u.loyalty_card)

    @app.post("/admin/users/<int:user_id>/set-role")
    @role_required("admin")
    def admin_set_role(user_id: int):
        require_csrf()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        new_role = request.form.get("role") or "customer"
        if new_role not in ("customer", "staff", "admin"):
            abort(400)

        u.role = new_role
        db.session.commit()
        flash(f"Updated role for {u.username} to {new_role}.", "success")
        return redirect(url_for("admin_user_view", user_id=user_id))

    @app.post("/admin/users/<int:user_id>/toggle-active")
    @role_required("admin")
    def admin_toggle_active(user_id: int):
        require_csrf()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        # prevent locking yourself out (optional but smart)
        if u.id == session.get("user_id"):
            flash("You can’t deactivate your own account.", "danger")
            return redirect(url_for("admin_user_view", user_id=user_id))

        u.is_active = not u.is_active
        db.session.commit()
        flash(f"{u.username} is now {'active' if u.is_active else 'inactive'}.", "success")
        return redirect(url_for("admin_user_view", user_id=user_id))

    @app.post("/admin/users/<int:user_id>/reset-loyalty")
    @role_required("admin")
    def admin_reset_loyalty(user_id: int):
        require_csrf()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        if not u.loyalty_card:
            db.session.add(LoyaltyCard(user_id=u.id))
            db.session.commit()

        u.loyalty_card.stamp_count = 0
        u.loyalty_card.reward_available = False
        db.session.commit()

        flash(f"Reset loyalty for {u.username}.", "success")
        return redirect(url_for("admin_user_view", user_id=user_id))

    # Keep your existing admin create-user route if you already have it.
    @app.route("/admin/create-user", methods=["GET", "POST"])
    @role_required("admin")
    def admin_create_user():
        if request.method == "POST":
            require_csrf()

            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            role = request.form.get("role") or "customer"

            if role not in ("customer", "staff", "admin"):
                abort(400)

            if not username or not email or len(password) < 8:
                flash("Invalid details (password must be 8+ chars).", "danger")
                return redirect(url_for("admin_create_user"))

            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return redirect(url_for("admin_create_user"))
            if User.query.filter_by(email=email).first():
                flash("Email already exists.", "danger")
                return redirect(url_for("admin_create_user"))

            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=role,
                is_active=True
            )
            db.session.add(new_user)
            db.session.flush()
            db.session.add(LoyaltyCard(user_id=new_user.id))
            db.session.commit()

            flash(f"Created {role} account for {username}.", "success")
            return redirect(url_for("admin_create_user"))

        return render_template("admin_create_user.html")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
