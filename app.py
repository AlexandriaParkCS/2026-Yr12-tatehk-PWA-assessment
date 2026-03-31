import os
import io
import csv
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from types import SimpleNamespace

import qrcode
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort,
    send_file, jsonify, send_from_directory, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_, func

from models import (
    db,
    User,
    BlockedContact,
    Cafe,
    CafeMember,
    CafeCustomerNote,
    UserContact,
    CafeSettings,
    RewardTier,
    LoyaltyCard,
    ActivityLog,
    StaffInvite,
    PasswordResetToken,
    EmailVerificationToken,
    Notification,
)
from routes_auth import register_auth_routes
from routes_customer import register_customer_routes
from routes_staff import register_staff_routes
from routes_manager import register_manager_routes
from routes_admin import register_admin_routes
from app_services import (
    apply_loyalty_increment,
    assign_membership_role,
    blocked_contact_message,
    build_action_note,
    build_default_cafe_settings,
    cafe_is_available,
    create_notification,
    customer_is_suspended,
    ensure_cafe_settings,
    ensure_email_settings,
    ensure_global_settings,
    ensure_loyalty_card,
    ensure_sqlite_schema_updates,
    get_active_reward_tiers,
    get_best_unlocked_tier,
    get_blocked_contact,
    get_cafe_owner_membership,
    get_customer_meta,
    get_email_branding,
    get_loyalty_progress,
    get_next_tier,
    get_user_block,
    get_user_contact,
    get_valid_email_verification,
    get_valid_password_reset,
    is_ajax_request,
    is_manager_role,
    is_protected_super_admin,
    log_activity,
    normalize_email,
    normalize_phone,
    reset_loyalty,
    seed_global_admin,
    send_app_email,
    send_email_verification_email,
    send_new_user_setup_email,
    send_staff_invite_email,
    slugify,
    update_customer_suspension,
    upsert_customer_meta,
    upsert_user_contact,
)

# ---------------------------
# App factory
# ---------------------------
def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        "sqlite:///coffee_loyalty_multi_v4.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    db.init_app(app)

    with app.app_context():
        db.create_all()
        ensure_sqlite_schema_updates()
        ensure_global_settings()
        ensure_email_settings()
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
        if cafe_is_available(cafe):
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
            return (
                Cafe.query
                .filter(Cafe.is_active == True, Cafe.is_archived == False)  # noqa: E712
                .order_by(Cafe.name.asc())
                .all()
            )

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
            .filter(Cafe.is_active == True, Cafe.is_archived == False)  # noqa: E712
            .outerjoin(CafeMember, cm_join)
            .outerjoin(LoyaltyCard, lc_join)
            .filter(or_(CafeMember.id.isnot(None), LoyaltyCard.id.isnot(None)))
            .order_by(Cafe.name.asc())
            .all()
        )
        return cafes

    def user_can_access_cafe(u: User | None, cafe: Cafe | None) -> bool:
        if not u or not cafe or not cafe_is_available(cafe):
            return False
        if is_global_admin(u):
            return True
        member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
        has_card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
        return bool(member or has_card)

    def render_card_page_for_user(u: User, cafe: Cafe):
        settings = ensure_cafe_settings(cafe)
        card = ensure_loyalty_card(u, cafe)
        progress = get_loyalty_progress(card, settings, cafe.id)
        tiers = get_active_reward_tiers(cafe.id) if settings.loyalty_type == "tiered_points" else []
        return render_template("card.html", card=card, settings=settings, progress=progress, tiers=tiers)

    def render_card_history_page_for_user(u: User, cafe: Cafe):
        history = (
            ActivityLog.query
            .filter_by(cafe_id=cafe.id, target_user_id=u.id)
            .order_by(ActivityLog.created_at.desc())
            .limit(100)
            .all()
        )
        return render_template("card_history.html", history=history)

    def render_staff_home_page(cafe: Cafe):
        settings = ensure_cafe_settings(cafe)
        tiers = get_active_reward_tiers(cafe.id) if settings.loyalty_type == "tiered_points" else []
        recent_activity = (
            ActivityLog.query
            .filter(ActivityLog.cafe_id == cafe.id)
            .filter(ActivityLog.action.in_(["stamp_added", "points_added", "reward_redeemed"]))
            .order_by(ActivityLog.created_at.desc())
            .limit(20)
            .all()
        )
        recent_customers = []
        seen_user_ids = set()
        for item in recent_activity:
            if item.target_user_id in seen_user_ids:
                continue
            u = db.session.get(User, item.target_user_id)
            if not u or u.is_global_admin:
                continue
            card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not card:
                continue
            progress = get_loyalty_progress(card, settings, cafe.id)
            meta = get_customer_meta(cafe.id, u.id)
            recent_customers.append((u, card, progress, meta, item))
            seen_user_ids.add(u.id)
            if len(recent_customers) >= 6:
                break
        return render_template("staff.html", settings=settings, tiers=tiers, recent_customers=recent_customers)

    def render_manager_dashboard_page(cafe: Cafe):
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
            progress = get_loyalty_progress(c, settings, cafe.id)
            meta = get_customer_meta(cafe.id, u.id)
            rows.append((u, c, progress, meta))

        total_customers = LoyaltyCard.query.filter_by(cafe_id=cafe.id).count()
        rewards_ready = LoyaltyCard.query.filter_by(cafe_id=cafe.id, reward_available=True).count()

        today = datetime.utcnow().date()
        if settings.loyalty_type in ("points", "tiered_points"):
            activity_today = (
                db.session.query(func.coalesce(func.sum(ActivityLog.points_delta), 0))
                .filter(ActivityLog.cafe_id == cafe.id)
                .filter(ActivityLog.action == "points_added")
                .filter(func.date(ActivityLog.created_at) == today)
                .scalar()
            ) or 0
        else:
            activity_today = (
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

        tiers = get_active_reward_tiers(cafe.id) if settings.loyalty_type == "tiered_points" else []

        return render_template(
            "manager_dashboard.html",
            rows=rows,
            settings=settings,
            total_customers=total_customers,
            rewards_ready=rewards_ready,
            activity_today=activity_today,
            stamps_today=activity_today,
            recent_activity=recent_activity,
            tiers=tiers,
        )

    def render_manager_audit_page(cafe: Cafe, action_filter: str, q: str):
        query = ActivityLog.query.filter_by(cafe_id=cafe.id)
        if action_filter:
            grouped_actions = {
                "invites": ["invite_created", "invite_revoked", "invite_accepted", "existing_user_added_to_cafe"],
                "scans": ["stamp_added", "points_added"],
                "redemptions": ["reward_redeemed", "loyalty_reset"],
                "passwords": ["password_changed"],
                "settings": ["settings_updated"],
                "staff": ["membership_added", "membership_removed", "membership_role_changed", "customer_note_updated", "customer_suspended", "customer_reactivated"],
            }
            if action_filter in grouped_actions:
                query = query.filter(ActivityLog.action.in_(grouped_actions[action_filter]))
            else:
                query = query.filter(ActivityLog.action == action_filter)

        items = query.order_by(ActivityLog.created_at.desc()).limit(200).all()
        rows = []
        for item in items:
            actor = db.session.get(User, item.actor_user_id) if item.actor_user_id else None
            target = db.session.get(User, item.target_user_id) if item.target_user_id else None
            haystack = " ".join(filter(None, [
                actor.username if actor else "",
                target.username if target else "",
                target.email if target else "",
                item.action,
                item.note or "",
            ])).lower()
            if q and q not in haystack:
                continue
            rows.append((item, actor, target))

        return render_template("manager_audit.html", rows=rows, action_filter=action_filter, q=q)

    def render_manager_staff_page(cafe: Cafe, invite_status: str):
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
        owner_membership = next((m for _, m in rows if m.role == "owner"), None)

        active_invites = (
            StaffInvite.query.filter_by(cafe_id=cafe.id, is_active=True)
            .filter(StaffInvite.accepted_at.is_(None))
            .filter(StaffInvite.expires_at >= datetime.utcnow())
            .order_by(StaffInvite.created_at.desc())
            .all()
        )

        invite_query = StaffInvite.query.filter_by(cafe_id=cafe.id)
        if invite_status == "accepted":
            invite_query = invite_query.filter(StaffInvite.accepted_at.isnot(None))
        elif invite_status == "revoked":
            invite_query = invite_query.filter(StaffInvite.is_active == False).filter(StaffInvite.accepted_at.is_(None))
        elif invite_status == "expired":
            invite_query = invite_query.filter(StaffInvite.expires_at < datetime.utcnow()).filter(StaffInvite.accepted_at.is_(None))
        else:
            invite_query = invite_query.filter(StaffInvite.is_active == True).filter(StaffInvite.accepted_at.is_(None)).filter(StaffInvite.expires_at >= datetime.utcnow())

        invite_history = invite_query.order_by(StaffInvite.created_at.desc()).limit(100).all()
        return render_template(
            "manager_staff.html",
            rows=rows,
            invites=active_invites,
            invite_history=invite_history,
            invite_status=invite_status,
            current_time=datetime.utcnow(),
            owner_membership=owner_membership,
        )

    def render_manager_customers_page(cafe: Cafe, q: str):
        settings = ensure_cafe_settings(cafe)
        cards = LoyaltyCard.query.filter_by(cafe_id=cafe.id).order_by(LoyaltyCard.updated_at.desc()).all()
        rows = []
        for card in cards:
            u = db.session.get(User, card.user_id)
            if not u or u.is_global_admin:
                continue
            progress = get_loyalty_progress(card, settings, cafe.id)
            meta = get_customer_meta(cafe.id, u.id)
            contact = get_user_contact(u.id)
            haystack = " ".join(filter(None, [
                u.username,
                u.email,
                contact.phone_number if contact and contact.phone_number else "",
                meta.note if meta and meta.note else "",
                meta.suspension_reason if meta and meta.suspension_reason else "",
            ])).lower()
            if q and q not in haystack:
                continue
            rows.append((u, card, progress, meta, contact))

        if request.args.get("format") == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Username", "Email", "Phone", "Current", "Required", "Unit", "Reward Ready", "Flagged", "Suspended", "Note", "Last Activity"])
            for u, card, progress, meta, contact in rows:
                writer.writerow([
                    u.username,
                    u.email,
                    contact.phone_number if contact and contact.phone_number else "",
                    progress["current"],
                    progress["required"],
                    progress["unit_label"],
                    "Yes" if card.reward_available else "No",
                    "Yes" if meta and meta.is_flagged else "No",
                    "Yes" if meta and meta.is_suspended else "No",
                    meta.note if meta and meta.note else "",
                    card.last_activity_at.isoformat() if card.last_activity_at else "",
                ])
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={cafe.slug}-customers.csv"}
            )

        return render_template("manager_customers.html", rows=rows, q=q)

    def render_manager_customer_profile_page(cafe: Cafe, customer: User):
        settings = ensure_cafe_settings(cafe)
        card = LoyaltyCard.query.filter_by(user_id=customer.id, cafe_id=cafe.id).first()
        progress = get_loyalty_progress(card, settings, cafe.id) if card else None
        meta = get_customer_meta(cafe.id, customer.id)
        contact = get_user_contact(customer.id)
        history = (
            ActivityLog.query
            .filter_by(cafe_id=cafe.id, target_user_id=customer.id)
            .order_by(ActivityLog.created_at.desc())
            .limit(50)
            .all()
        )
        actor_ids = {item.actor_user_id for item in history if item.actor_user_id}
        actor_ids.update(
            {
                meta.updated_by_user_id if meta and meta.updated_by_user_id else None,
                meta.suspended_by_user_id if meta and meta.suspended_by_user_id else None,
            }
        )
        actor_ids.discard(None)
        actor_map = {actor_id: db.session.get(User, actor_id) for actor_id in actor_ids}
        return render_template(
            "manager_customer_profile.html",
            customer=customer,
            card=card,
            progress=progress,
            meta=meta,
            contact=contact,
            history=history,
            actor_map=actor_map,
            settings=settings,
        )

    def render_cafe_settings_page(u: User, cafe: Cafe):
        if not is_global_admin(u):
            m = get_membership(u, cafe)
            if not m or not is_manager_role(m.role):
                abort(403)

        settings = ensure_cafe_settings(cafe)
        tiers = get_active_reward_tiers(cafe.id)
        return render_template("cafe_settings.html", settings=settings, tiers=tiers)

    def redirect_cafe_staff(cafe: Cafe):
        return redirect(url_for("cafe_staff", cafe_slug=cafe.slug))

    def redirect_cafe_manager_dashboard(cafe: Cafe):
        return redirect(url_for("cafe_manager_dashboard", cafe_slug=cafe.slug))

    def redirect_cafe_manager_staff(cafe: Cafe, *, invite_status: str | None = None):
        kwargs = {"cafe_slug": cafe.slug}
        if invite_status:
            kwargs["invite_status"] = invite_status
        return redirect(url_for("cafe_manager_staff", **kwargs))

    def redirect_cafe_settings_page(cafe: Cafe):
        return redirect(url_for("cafe_slug_settings", cafe_slug=cafe.slug))

    def redirect_cafe_manager_customers(cafe: Cafe):
        return redirect(url_for("cafe_manager_customers", cafe_slug=cafe.slug))

    def require_login(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u or not u.is_active:
                session.clear()
                flash("Please log in.", "warning")
                return redirect(url_for("login"))
            blocked = get_user_block(u)
            if blocked:
                session.clear()
                flash(blocked_contact_message(blocked), "danger")
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
                if not m:
                    abort(403)
                if m.role not in roles and not (m.role == "owner" and "manager" in roles):
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
        if not token_form or not token_session or token_form != token_session:
            abort(400, description="CSRF token missing/invalid")

    @app.context_processor
    def inject_globals():
        u = current_user()
        cafe = current_cafe()
        global_settings = ensure_global_settings()
        email_settings = ensure_email_settings()
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
            "global_settings": global_settings,
            "email_settings": email_settings,
            "me_membership": membership,
            "me_is_admin": is_global_admin(u),
            "me_pending_setup": bool(u and getattr(u, "requires_password_setup", False)),
            "me_email_verified": bool(u and (u.is_global_admin or not getattr(u, "requires_email_verification", False))),
            "unread_notifications": unread_notifications,
        }

    @app.errorhandler(400)
    def handle_400(err):
        session.pop("csrf_token", None)
        flash("Session expired — please try again.", "warning")
        return redirect(request.referrer or url_for("login"))

    @app.errorhandler(403)
    def handle_403(err):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def handle_404(err):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def handle_500(err):
        db.session.rollback()
        return render_template("500.html"), 500

    ctx = SimpleNamespace(
        current_user=current_user,
        current_cafe=current_cafe,
        is_global_admin=is_global_admin,
        get_membership=get_membership,
        cafes_accessible_to_user=cafes_accessible_to_user,
        user_can_access_cafe=user_can_access_cafe,
        render_card_page_for_user=render_card_page_for_user,
        render_card_history_page_for_user=render_card_history_page_for_user,
        render_staff_home_page=render_staff_home_page,
        render_manager_dashboard_page=render_manager_dashboard_page,
        render_manager_audit_page=render_manager_audit_page,
        render_manager_staff_page=render_manager_staff_page,
        render_manager_customers_page=render_manager_customers_page,
        render_manager_customer_profile_page=render_manager_customer_profile_page,
        render_cafe_settings_page=render_cafe_settings_page,
        redirect_cafe_staff=redirect_cafe_staff,
        redirect_cafe_manager_dashboard=redirect_cafe_manager_dashboard,
        redirect_cafe_manager_staff=redirect_cafe_manager_staff,
        redirect_cafe_settings_page=redirect_cafe_settings_page,
        redirect_cafe_manager_customers=redirect_cafe_manager_customers,
        require_login=require_login,
        require_cafe_selected=require_cafe_selected,
        require_global_admin=require_global_admin,
        require_role_in_cafe=require_role_in_cafe,
        require_csrf=require_csrf,
    )

    register_auth_routes(app, ctx)
    register_customer_routes(app, ctx)
    register_staff_routes(app, ctx)
    register_manager_routes(app, ctx)
    register_admin_routes(app, ctx)

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)


