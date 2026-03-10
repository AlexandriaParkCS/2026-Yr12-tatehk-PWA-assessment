import os
import io
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps

import qrcode
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort,
    send_file, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_, func

from models import (
    db,
    User,
    Cafe,
    CafeMember,
    CafeSettings,
    LoyaltyCard,
    ActivityLog,
    StaffInvite,
    Notification,
)


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

    card = LoyaltyCard(
        user_id=user.id,
        cafe_id=cafe.id,
        last_activity_at=datetime.utcnow()
    )
    db.session.add(card)
    db.session.commit()
    return card


def log_activity(
    *,
    cafe_id: int,
    action: str,
    target_user_id: int,
    actor_user_id: int | None = None,
    stamp_delta: int = 0,
    note: str | None = None
) -> None:
    row = ActivityLog(
        cafe_id=cafe_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        action=action,
        stamp_delta=stamp_delta,
        note=note,
    )
    db.session.add(row)
    db.session.commit()


def create_notification(user_id: int, cafe_id: int | None, title: str, message: str) -> None:
    n = Notification(
        user_id=user_id,
        cafe_id=cafe_id,
        title=title,
        message=message,
    )
    db.session.add(n)
    db.session.commit()


# ---------------------------
# App factory
# ---------------------------
def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        "sqlite:///coffee_loyalty_multi_v2.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    db.init_app(app)

    with app.app_context():
        db.create_all()
        seed_global_admin()

    # ---------------------------
    # Session / auth helpers
    # ---------------------------
    def current_user():
        uid = session.get("user_id")
        return db.session.get(User, uid) if uid else None

    def current_cafe():
        cid = session.get("cafe_id")
        if not cid:
            return None
        cafe = db.session.get(Cafe, cid)
        if cafe and cafe.is_active:
            return cafe
        return None

    def is_global_admin(u: User | None) -> bool:
        return bool(u and u.is_global_admin and u.is_active)

    def get_membership(u: User | None, cafe: Cafe | None):
        if not u or not cafe:
            return None
        return CafeMember.query.filter_by(
            user_id=u.id,
            cafe_id=cafe.id,
            is_active=True
        ).first()

    def cafes_accessible_to_user(u: User | None):
        if not u:
            return []

        if is_global_admin(u):
            return Cafe.query.filter_by(is_active=True).order_by(Cafe.name.asc()).all()

        cm_join = and_(
            CafeMember.cafe_id == Cafe.id,
            CafeMember.user_id == u.id,
            CafeMember.is_active == True,  # noqa: E712
        )
        lc_join = and_(
            LoyaltyCard.cafe_id == Cafe.id,
            LoyaltyCard.user_id == u.id,
        )

        cafes = (
            Cafe.query
            .filter(Cafe.is_active == True)  # noqa: E712
            .outerjoin(CafeMember, cm_join)
            .outerjoin(LoyaltyCard, lc_join)
            .filter(or_(CafeMember.id.isnot(None), LoyaltyCard.id.isnot(None)))
            .order_by(Cafe.name.asc())
            .all()
        )
        return cafes

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
                flash("No cafe selected. Pick a cafe first.", "warning")
                return redirect(url_for("select_cafe"))
            return fn(*args, **kwargs)
        return wrapper

    def require_global_admin(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_global_admin(current_user()):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper

    def require_role_in_cafe(*roles):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                u = current_user()
                cafe = current_cafe()

                if not u or not u.is_active:
                    return redirect(url_for("login"))
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
    # CSRF
    # ---------------------------
    def get_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    def require_csrf():
        token_form = request.form.get("csrf_token", "")
        token_session = session.get("csrf_token", "")
        if not token_form or token_form != token_session:
            abort(400, description="CSRF token missing/invalid")

    @app.context_processor
    def inject_globals():
        u = current_user()
        cafe = current_cafe()
        membership = None
        if u and cafe and not is_global_admin(u):
            membership = get_membership(u, cafe)

        unread_notifications = []
        if u:
            unread_notifications = (
                Notification.query
                .filter_by(user_id=u.id, is_read=False)
                .order_by(Notification.created_at.desc())
                .limit(5)
                .all()
            )

        return {
            "csrf_token": get_csrf_token(),
            "me": u,
            "active_cafe": cafe,
            "me_membership": membership,
            "me_is_admin": is_global_admin(u),
            "unread_notifications": unread_notifications,
        }

    @app.errorhandler(400)
    def handle_400(err):
        session.pop("csrf_token", None)
        flash("Session expired — please try again.", "warning")
        return redirect(request.referrer or url_for("login"))

    # ---------------------------
    # Home / auth
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
                is_active=True,
                is_global_admin=False,
            )
            db.session.add(user)
            db.session.commit()

            session.clear()
            session["user_id"] = user.id
            session["csrf_token"] = secrets.token_urlsafe(32)

            create_notification(
                user.id,
                None,
                "Welcome",
                "Your account is ready. Show your QR code at a cafe to start earning stamps."
            )

            flash("Account created.", "success")
            return redirect(url_for("my_qr"))

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

            if not is_global_admin(user):
                return redirect(url_for("my_qr"))
            return redirect(url_for("select_cafe"))

        return render_template("login.html")

    @app.post("/logout")
    def logout():
        require_csrf()
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("index"))

    # ---------------------------
    # Notifications
    # ---------------------------
    @app.post("/notifications/<int:notification_id>/read")
    @require_login
    def mark_notification_read(notification_id: int):
        require_csrf()
        n = db.session.get(Notification, notification_id)
        u = current_user()
        if not n or n.user_id != u.id:
            abort(404)
        n.is_read = True
        db.session.commit()
        return redirect(request.referrer or url_for("my_qr"))

    # ---------------------------
    # QR / customer pages
    # ---------------------------
    @app.get("/my-qr")
    @require_login
    def my_qr():
        u = current_user()
        cafes = cafes_accessible_to_user(u)
        return render_template("my_qr.html", cafes=cafes)

    @app.get("/my-stamps")
    @require_login
    def my_stamps():
        u = current_user()
        cards = (
            LoyaltyCard.query
            .filter_by(user_id=u.id)
            .order_by(LoyaltyCard.updated_at.desc())
            .all()
        )

        rows = []
        for card in cards:
            cafe = db.session.get(Cafe, card.cafe_id)
            if not cafe or not cafe.is_active:
                continue
            settings = ensure_cafe_settings(cafe)
            rows.append((cafe, card, settings))

        return render_template("my_stamps.html", rows=rows)

    @app.get("/select-cafe")
    @require_login
    def select_cafe():
        cafes = cafes_accessible_to_user(current_user())
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
            member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            has_card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not member and not has_card:
                flash("You don’t have access to that cafe yet. Ask staff to scan your QR first.", "danger")
                return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id

        if is_global_admin(u):
            return redirect(url_for("staff_home"))

        m = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
        if m and m.role in ("staff", "manager"):
            return redirect(url_for("staff_home"))

        return redirect(url_for("card"))

    @app.post("/switch-cafe")
    @require_login
    def switch_cafe():
        return select_cafe_post()

    @app.get("/card")
    @require_login
    @require_cafe_selected
    def card():
        u = current_user()
        cafe = current_cafe()
        settings = ensure_cafe_settings(cafe)
        card = ensure_loyalty_card(u, cafe)
        return render_template("card.html", card=card, settings=settings)

    @app.get("/qr/<token>")
    @require_login
    def qr_image(token):
        u = current_user()
        if not is_global_admin(u) and u.qr_token != token:
            abort(403)

        img = qrcode.make(token)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")

    # ---------------------------
    # Staff scanner / actions
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
            "user": {"id": u.id, "username": u.username, "email": u.email},
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
        actor = current_user()
        settings = ensure_cafe_settings(cafe)

        token = (request.form.get("token") or "").strip()
        if not token:
            flash("No token provided.", "danger")
            return redirect(url_for("staff_home"))

        if not settings.staff_can_add_stamp and not is_global_admin(actor):
            flash("Stamp adding is disabled for staff at this cafe.", "danger")
            return redirect(url_for("staff_home"))

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            flash("User not found.", "danger")
            return redirect(url_for("staff_home"))

        card = ensure_loyalty_card(u, cafe)

        if card.reward_available:
            flash("Reward already available — redeem first.", "warning")
            return redirect(url_for("staff_home"))

        if card.stamp_count < settings.stamps_required:
            card.stamp_count += 1
            if card.stamp_count >= settings.stamps_required:
                card.stamp_count = settings.stamps_required
                card.reward_available = True

        now = datetime.utcnow()
        card.last_scan_at = now
        card.last_activity_at = now
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=u.id,
            action="stamp_added",
            stamp_delta=1,
            note=f"{actor.username} added a stamp"
        )

        create_notification(
            u.id,
            cafe.id,
            "Stamp added",
            f"You received a stamp at {cafe.name}. You now have {card.stamp_count}/{settings.stamps_required}."
        )

        flash(f"Stamp added to {u.username}.", "success")
        return redirect(url_for("staff_home"))

    @app.post("/staff/redeem-by-token")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_redeem_by_token():
        require_csrf()
        cafe = current_cafe()
        actor = current_user()
        settings = ensure_cafe_settings(cafe)

        token = (request.form.get("token") or "").strip()
        if not token:
            flash("No token provided.", "danger")
            return redirect(url_for("staff_home"))

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            flash("User not found.", "danger")
            return redirect(url_for("staff_home"))

        membership = get_membership(actor, cafe)
        if membership and membership.role == "staff" and not settings.staff_can_redeem:
            flash("Staff are not allowed to redeem at this cafe.", "danger")
            return redirect(url_for("staff_home"))

        card = ensure_loyalty_card(u, cafe)
        if not card.reward_available:
            flash("No reward available yet.", "warning")
            return redirect(url_for("staff_home"))

        card.stamp_count = 0
        card.reward_available = False
        now = datetime.utcnow()
        card.last_redeem_at = now
        card.last_activity_at = now
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=u.id,
            action="reward_redeemed",
            stamp_delta=0,
            note=f"{settings.reward_name} redeemed"
        )

        create_notification(
            u.id,
            cafe.id,
            "Reward redeemed",
            f"Your {settings.reward_name} was redeemed at {cafe.name}."
        )

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
            stamps = card.stamp_count if card else 0
            reward = bool(card.reward_available) if card else False
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
    # Manager dashboard / staff / settings
    # ---------------------------
    @app.get("/manager")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_dashboard():
        cafe = current_cafe()
        settings = ensure_cafe_settings(cafe)

        cards = (
            LoyaltyCard.query.filter_by(cafe_id=cafe.id)
            .order_by(LoyaltyCard.updated_at.desc())
            .limit(300)
            .all()
        )

        rows = []
        for c in cards:
            u = db.session.get(User, c.user_id)
            if not u or u.is_global_admin:
                continue
            rows.append((u, c))

        # Stats
        total_customers = LoyaltyCard.query.filter_by(cafe_id=cafe.id).count()
        rewards_ready = LoyaltyCard.query.filter_by(cafe_id=cafe.id, reward_available=True).count()

        today = datetime.utcnow().date()
        stamps_today = (
            db.session.query(func.count(ActivityLog.id))
            .filter(ActivityLog.cafe_id == cafe.id)
            .filter(ActivityLog.action == "stamp_added")
            .filter(func.date(ActivityLog.created_at) == today)
            .scalar()
        ) or 0

        recent_activity = (
            ActivityLog.query.filter_by(cafe_id=cafe.id)
            .order_by(ActivityLog.created_at.desc())
            .limit(10)
            .all()
        )

        return render_template(
            "manager_dashboard.html",
            rows=rows,
            settings=settings,
            total_customers=total_customers,
            rewards_ready=rewards_ready,
            stamps_today=stamps_today,
            recent_activity=recent_activity,
        )

    @app.post("/manager/reset-loyalty")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_reset_loyalty():
        require_csrf()
        cafe = current_cafe()
        actor = current_user()

        user_id = request.form.get("user_id")
        if not user_id or not user_id.isdigit():
            flash("Invalid user.", "danger")
            return redirect(url_for("manager_dashboard"))

        u = db.session.get(User, int(user_id))
        if not u or u.is_global_admin:
            flash("User not found.", "danger")
            return redirect(url_for("manager_dashboard"))

        settings = ensure_cafe_settings(cafe)
        membership = get_membership(actor, cafe)
        if membership and membership.role == "staff" and not settings.staff_can_reset_loyalty:
            flash("Staff cannot reset loyalty here.", "danger")
            return redirect(url_for("manager_dashboard"))

        card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
        if not card:
            flash("No loyalty card for this user at this cafe.", "warning")
            return redirect(url_for("manager_dashboard"))

        card.stamp_count = 0
        card.reward_available = False
        card.last_activity_at = datetime.utcnow()
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=u.id,
            action="loyalty_reset",
            note="Manager reset loyalty"
        )

        flash(f"Reset loyalty for {u.username}.", "success")
        return redirect(url_for("manager_dashboard"))

    @app.get("/manager/staff")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_staff():
        cafe = current_cafe()

        members = (
            CafeMember.query.filter_by(cafe_id=cafe.id)
            .order_by(CafeMember.role.asc(), CafeMember.created_at.desc())
            .all()
        )

        rows = []
        for m in members:
            u = db.session.get(User, m.user_id)
            if not u or u.is_global_admin:
                continue
            rows.append((u, m))

        invites = (
            StaffInvite.query.filter_by(cafe_id=cafe.id, is_active=True)
            .order_by(StaffInvite.created_at.desc())
            .all()
        )

        return render_template("manager_staff.html", rows=rows, invites=invites)

    @app.post("/manager/staff/add")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_staff_add():
        require_csrf()
        cafe = current_cafe()

        identifier = (request.form.get("identifier") or "").strip()
        role = (request.form.get("role") or "staff").strip().lower()
        if role not in ("staff", "manager"):
            role = "staff"

        if not identifier:
            flash("Enter a username or email.", "danger")
            return redirect(url_for("manager_staff"))

        u = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if not u:
            flash("User not found.", "danger")
            return redirect(url_for("manager_staff"))
        if u.is_global_admin:
            flash("Cannot assign global admins.", "danger")
            return redirect(url_for("manager_staff"))

        mem = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
        if not mem:
            mem = CafeMember(user_id=u.id, cafe_id=cafe.id, role=role, is_active=True)
            db.session.add(mem)
        else:
            mem.role = role
            mem.is_active = True

        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=current_user().id,
            target_user_id=u.id,
            action="membership_added",
            note=f"Assigned as {role}"
        )

        flash(f"Added {u.username} as {role} at {cafe.name}.", "success")
        return redirect(url_for("manager_staff"))

    @app.post("/manager/staff/update")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_staff_update():
        require_csrf()
        cafe = current_cafe()

        member_id = request.form.get("member_id", "")
        action = (request.form.get("action") or "").strip()

        if not member_id.isdigit():
            flash("Invalid member.", "danger")
            return redirect(url_for("manager_staff"))

        mem = db.session.get(CafeMember, int(member_id))
        if not mem or mem.cafe_id != cafe.id:
            flash("Member not found.", "danger")
            return redirect(url_for("manager_staff"))

        u = db.session.get(User, mem.user_id)
        if not u or u.is_global_admin:
            flash("Cannot edit this user.", "danger")
            return redirect(url_for("manager_staff"))

        if action == "deactivate":
            mem.is_active = False
            db.session.commit()
            log_activity(
                cafe_id=cafe.id,
                actor_user_id=current_user().id,
                target_user_id=u.id,
                action="membership_removed",
                note="Removed from cafe"
            )
            flash(f"Removed {u.username} from this cafe.", "success")
            return redirect(url_for("manager_staff"))

        if action == "set_role":
            role = (request.form.get("role") or "").strip().lower()
            if role not in ("staff", "manager"):
                flash("Invalid role.", "danger")
                return redirect(url_for("manager_staff"))
            mem.role = role
            mem.is_active = True
            db.session.commit()
            flash(f"Updated {u.username} to {role}.", "success")
            return redirect(url_for("manager_staff"))

        flash("Unknown action.", "danger")
        return redirect(url_for("manager_staff"))

    @app.post("/manager/staff/set-password")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_staff_set_password():
        require_csrf()
        cafe = current_cafe()

        member_id = request.form.get("member_id", "")
        new_password = request.form.get("new_password") or ""

        if not member_id.isdigit():
            flash("Invalid member.", "danger")
            return redirect(url_for("manager_staff"))
        if len(new_password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("manager_staff"))

        mem = db.session.get(CafeMember, int(member_id))
        if not mem or mem.cafe_id != cafe.id or not mem.is_active:
            flash("Member not found.", "danger")
            return redirect(url_for("manager_staff"))

        target_user = db.session.get(User, mem.user_id)
        if not target_user or target_user.is_global_admin:
            flash("Cannot change this user.", "danger")
            return redirect(url_for("manager_staff"))

        target_user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=current_user().id,
            target_user_id=target_user.id,
            action="password_changed",
            note="Manager changed password"
        )

        flash(f"Password updated for {target_user.username}.", "success")
        return redirect(url_for("manager_staff"))

    @app.post("/manager/invites/create")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_create_invite():
        require_csrf()
        cafe = current_cafe()

        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or "staff").strip().lower()
        if role not in ("staff", "manager"):
            role = "staff"

        if not email:
            flash("Email is required.", "danger")
            return redirect(url_for("manager_staff"))

        invite = StaffInvite(
            cafe_id=cafe.id,
            created_by_user_id=current_user().id,
            email=email,
            role=role,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active=True,
        )
        db.session.add(invite)
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=current_user().id,
            target_user_id=current_user().id,
            action="invite_created",
            note=f"Invite created for {email} as {role}"
        )

        flash("Invite created.", "success")
        return redirect(url_for("manager_staff"))

    @app.get("/settings")
    @require_login
    @require_cafe_selected
    def cafe_settings():
        u = current_user()
        cafe = current_cafe()

        if not is_global_admin(u):
            m = get_membership(u, cafe)
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
            m = get_membership(u, cafe)
            if not m or m.role != "manager":
                abort(403)

        settings = ensure_cafe_settings(cafe)

        stamps_required = (request.form.get("stamps_required") or "").strip()
        reward_name = (request.form.get("reward_name") or "").strip()

        settings.stamps_required = int(stamps_required) if stamps_required.isdigit() else settings.stamps_required
        settings.reward_name = reward_name or settings.reward_name
        settings.staff_can_scan = request.form.get("staff_can_scan") == "on"
        settings.staff_can_add_stamp = request.form.get("staff_can_add_stamp") == "on"
        settings.staff_can_redeem = request.form.get("staff_can_redeem") == "on"
        settings.staff_can_reset_loyalty = request.form.get("staff_can_reset_loyalty") == "on"

        db.session.commit()
        flash("Settings updated.", "success")
        return redirect(url_for("cafe_settings"))

    # ---------------------------
    # Admin cafe management
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

        db.session.add(CafeSettings(cafe_id=cafe.id))

        if manager_email:
            manager_user = User.query.filter_by(email=manager_email).first()
            if not manager_user:
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

            existing = CafeMember.query.filter_by(user_id=manager_user.id, cafe_id=cafe.id).first()
            if not existing:
                db.session.add(CafeMember(
                    user_id=manager_user.id,
                    cafe_id=cafe.id,
                    role="manager",
                    is_active=True
                ))

        db.session.commit()
        flash(f"Created cafe '{cafe.name}'.", "success")
        return redirect(url_for("select_cafe"))

    # ---------------------------
    # Admin user management
    # ---------------------------
    @app.get("/admin/users")
    @require_login
    @require_global_admin
    def admin_users():
        q = (request.args.get("q") or "").strip()

        query = User.query
        if q:
            query = query.filter(
                (User.username.ilike(f"%{q}%")) | (User.email.ilike(f"%{q}%"))
            )

        users = query.order_by(User.created_at.desc()).limit(300).all()
        return render_template("admin_users.html", users=users, q=q)

    @app.route("/admin/users/create", methods=["GET", "POST"])
    @require_login
    @require_global_admin
    def admin_user_create():
        if request.method == "POST":
            require_csrf()

            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            is_admin = request.form.get("is_global_admin") == "on"
            is_active = request.form.get("is_active") == "on"

            if not username or not email or not password:
                flash("Username, email, and password required.", "danger")
                return redirect(url_for("admin_user_create"))
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return redirect(url_for("admin_user_create"))
            if User.query.filter_by(username=username).first():
                flash("Username already taken.", "danger")
                return redirect(url_for("admin_user_create"))
            if User.query.filter_by(email=email).first():
                flash("Email already used.", "danger")
                return redirect(url_for("admin_user_create"))

            u = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                is_active=is_active,
                is_global_admin=is_admin,
            )
            db.session.add(u)
            db.session.commit()

            flash("User created.", "success")
            return redirect(url_for("admin_users"))

        cafes = Cafe.query.filter_by(is_active=True).order_by(Cafe.name.asc()).all()
        return render_template("admin_user_create.html", cafes=cafes)

    @app.get("/admin/users/<int:user_id>")
    @require_login
    @require_global_admin
    def admin_user_manage(user_id: int):
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        cafes = Cafe.query.filter_by(is_active=True).order_by(Cafe.name.asc()).all()
        memberships = CafeMember.query.filter_by(user_id=u.id).order_by(CafeMember.created_at.desc()).all()
        cafe_map = {c.id: c for c in cafes}

        return render_template(
            "admin_user_manage.html",
            target=u,
            cafes=cafes,
            memberships=memberships,
            cafe_map=cafe_map
        )

    @app.post("/admin/users/<int:user_id>/update")
    @require_login
    @require_global_admin
    def admin_user_update(user_id: int):
        require_csrf()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        action = (request.form.get("action") or "").strip()

        if action == "toggle_active":
            u.is_active = not u.is_active
            db.session.commit()
            flash("User status updated.", "success")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        if action == "set_global_admin":
            u.is_global_admin = request.form.get("value") == "true"
            db.session.commit()
            flash("Global admin flag updated.", "success")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        if action == "reset_password":
            pw = request.form.get("password") or ""
            if len(pw) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))
            u.password_hash = generate_password_hash(pw)
            db.session.commit()
            flash("Password reset.", "success")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        flash("Unknown action.", "danger")
        return redirect(url_for("admin_user_manage", user_id=user_id))

    @app.post("/admin/users/<int:user_id>/membership")
    @require_login
    @require_global_admin
    def admin_user_membership(user_id: int):
        require_csrf()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        action = (request.form.get("action") or "").strip()

        if action == "add_or_update":
            cafe_id = request.form.get("cafe_id", "")
            role = (request.form.get("role") or "staff").strip().lower()
            is_active = request.form.get("is_active") == "on"

            if role not in ("staff", "manager"):
                role = "staff"
            if not cafe_id.isdigit():
                flash("Pick a cafe.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))

            cafe = db.session.get(Cafe, int(cafe_id))
            if not cafe or not cafe.is_active:
                flash("Cafe not found.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))

            mem = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not mem:
                mem = CafeMember(user_id=u.id, cafe_id=cafe.id, role=role, is_active=is_active)
                db.session.add(mem)
            else:
                mem.role = role
                mem.is_active = is_active

            db.session.commit()
            flash("Membership saved.", "success")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        if action == "remove":
            member_id = request.form.get("member_id", "")
            if not member_id.isdigit():
                flash("Invalid membership.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))
            mem = db.session.get(CafeMember, int(member_id))
            if not mem or mem.user_id != u.id:
                flash("Membership not found.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))
            db.session.delete(mem)
            db.session.commit()
            flash("Membership removed.", "success")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        flash("Unknown action.", "danger")
        return redirect(url_for("admin_user_manage", user_id=user_id))

    return app


# ---------------------------
# Seed global admin
# ---------------------------
def seed_global_admin():
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