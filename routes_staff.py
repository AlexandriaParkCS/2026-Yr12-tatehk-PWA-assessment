import csv
import io
import re
import secrets
from datetime import datetime, timedelta

import qrcode
from flask import (
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
    Response,
)
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import and_, func, or_

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
    send_app_email,
    send_email_verification_email,
    send_new_user_setup_email,
    send_staff_invite_email,
    slugify,
    update_customer_suspension,
    upsert_customer_meta,
    upsert_user_contact,
)


def register_staff_routes(app, ctx):
    current_user = ctx.current_user
    current_cafe = ctx.current_cafe
    is_global_admin = ctx.is_global_admin
    get_membership = ctx.get_membership
    cafes_accessible_to_user = ctx.cafes_accessible_to_user
    user_can_access_cafe = ctx.user_can_access_cafe
    render_card_page_for_user = ctx.render_card_page_for_user
    render_card_history_page_for_user = ctx.render_card_history_page_for_user
    render_staff_home_page = ctx.render_staff_home_page
    render_manager_dashboard_page = ctx.render_manager_dashboard_page
    render_manager_audit_page = ctx.render_manager_audit_page
    render_manager_staff_page = ctx.render_manager_staff_page
    render_manager_customers_page = ctx.render_manager_customers_page
    render_manager_customer_profile_page = ctx.render_manager_customer_profile_page
    render_cafe_settings_page = ctx.render_cafe_settings_page
    redirect_cafe_staff = ctx.redirect_cafe_staff
    redirect_cafe_manager_dashboard = ctx.redirect_cafe_manager_dashboard
    redirect_cafe_manager_staff = ctx.redirect_cafe_manager_staff
    redirect_cafe_settings_page = ctx.redirect_cafe_settings_page
    redirect_cafe_manager_customers = ctx.redirect_cafe_manager_customers
    require_login = ctx.require_login
    require_cafe_selected = ctx.require_cafe_selected
    require_global_admin = ctx.require_global_admin
    require_role_in_cafe = ctx.require_role_in_cafe
    require_csrf = ctx.require_csrf
    # ---------------------------
    # Staff
    # ---------------------------
    @app.get("/staff")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_home():
        cafe = current_cafe()
        return render_staff_home_page(cafe)

    @app.get("/staff/lookup")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_lookup():
        cafe = current_cafe()
        settings = ensure_cafe_settings(cafe)

        token = (request.args.get("token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "Missing token"}), 400

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if customer_is_suspended(cafe.id, u.id):
            return jsonify({"ok": False, "error": "Customer is currently suspended at this cafe"}), 403

        if settings.auto_create_card_on_first_scan:
            card = ensure_loyalty_card(u, cafe)
        else:
            card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not card:
                return jsonify({"ok": False, "error": "Customer is not enrolled at this cafe"}), 404

        progress = get_loyalty_progress(card, settings, cafe.id)
        meta = get_customer_meta(cafe.id, u.id)
        contact = get_user_contact(u.id)

        return jsonify({
            "ok": True,
            "user": {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "phone_number": contact.phone_number if contact and contact.phone_number else "",
                "is_flagged": bool(meta.is_flagged) if meta else False,
                "is_suspended": bool(meta.is_suspended) if meta else False,
                "customer_note": meta.note if meta and meta.note else "",
                "suspension_reason": meta.suspension_reason if meta and meta.suspension_reason else "",
            },
            "card": {
                "reward_available": bool(card.reward_available),
                "reward_name": progress["reward_name"],
                "loyalty_type": settings.loyalty_type,
                "stamp_count": card.stamp_count,
                "points_balance": card.points_balance,
                "current": progress["current"],
                "required": progress["required"],
                "remaining": progress["remaining"],
                "progress": progress["progress"],
                "unit_label": progress["unit_label"],
                "next_tier_name": progress["next_tier"].reward_name if progress["next_tier"] else None,
                "next_tier_points": progress["next_tier"].points_required if progress["next_tier"] else None,
                "unlocked_tier_name": progress["unlocked_tier"].reward_name if progress["unlocked_tier"] else None,
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
        reason_code = (request.form.get("reason_code") or "").strip().lower()
        reason_note = (request.form.get("reason_note") or "").strip()

        token = (request.form.get("token") or "").strip()
        if not token:
            if is_ajax_request():
                return jsonify({"ok": False, "message": "No token provided."}), 400
            flash("No token provided.", "danger")
            return redirect(url_for("staff_home"))

        if not settings.staff_can_add_stamp and not is_global_admin(actor):
            if is_ajax_request():
                return jsonify({"ok": False, "message": "Adding loyalty progress is disabled for staff at this cafe."}), 403
            flash("Adding loyalty progress is disabled for staff at this cafe.", "danger")
            return redirect(url_for("staff_home"))

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            if is_ajax_request():
                return jsonify({"ok": False, "message": "User not found."}), 404
            flash("User not found.", "danger")
            return redirect(url_for("staff_home"))
        if customer_is_suspended(cafe.id, u.id):
            message = "Customer is currently suspended at this cafe."
            if is_ajax_request():
                return jsonify({"ok": False, "message": message}), 403
            flash(message, "danger")
            return redirect(url_for("staff_home"))

        if settings.auto_create_card_on_first_scan:
            card = ensure_loyalty_card(u, cafe)
        else:
            card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not card:
                if is_ajax_request():
                    return jsonify({"ok": False, "message": "Customer is not enrolled at this cafe."}), 400
                flash("Customer is not enrolled at this cafe.", "danger")
                return redirect(url_for("staff_home"))

        stamp_delta, points_delta = apply_loyalty_increment(card, settings, cafe.id)
        if stamp_delta == 0 and points_delta == 0 and card.reward_available:
            flash("Reward already available — redeem first.", "warning")
            return redirect(url_for("staff_home"))

        now = datetime.utcnow()
        card.last_scan_at = now
        card.last_activity_at = now
        db.session.commit()

        if settings.loyalty_type == "tiered_points":
            action = "points_added"
            note = build_action_note(actor.username, f"added {points_delta} points", reason_code, reason_note)
        elif settings.loyalty_type == "points":
            action = "points_added"
            note = build_action_note(actor.username, f"added {points_delta} points", reason_code, reason_note)
        else:
            action = "stamp_added"
            note = build_action_note(actor.username, "added a stamp", reason_code, reason_note)

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=u.id,
            action=action,
            stamp_delta=stamp_delta,
            points_delta=points_delta,
            note=note
        )

        if settings.enable_notifications:
            progress = get_loyalty_progress(card, settings, cafe.id)
            create_notification(
                u.id,
                cafe.id,
                "Loyalty updated",
                f"You now have {progress['current']}/{progress['required']} {progress['unit_label']} at {cafe.name}."
            )

        if settings.loyalty_type in ("points", "tiered_points"):
            message = f"Added {points_delta} points to {u.username}."
        else:
            message = f"Stamp added to {u.username}."
        if is_ajax_request():
            return jsonify({"ok": True, "message": message})
        flash(message, "success")
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
        reason_code = (request.form.get("reason_code") or "").strip().lower()
        reason_note = (request.form.get("reason_note") or "").strip()

        token = (request.form.get("token") or "").strip()
        if not token:
            if is_ajax_request():
                return jsonify({"ok": False, "message": "No token provided."}), 400
            flash("No token provided.", "danger")
            return redirect(url_for("staff_home"))

        u = User.query.filter_by(qr_token=token, is_active=True).first()
        if not u:
            if is_ajax_request():
                return jsonify({"ok": False, "message": "User not found."}), 404
            flash("User not found.", "danger")
            return redirect(url_for("staff_home"))
        if customer_is_suspended(cafe.id, u.id):
            message = "Customer is currently suspended at this cafe."
            if is_ajax_request():
                return jsonify({"ok": False, "message": message}), 403
            flash(message, "danger")
            return redirect(url_for("staff_home"))

        membership = get_membership(actor, cafe)
        if membership and membership.role == "staff" and not settings.staff_can_redeem:
            if is_ajax_request():
                return jsonify({"ok": False, "message": "Staff are not allowed to redeem at this cafe."}), 403
            flash("Staff are not allowed to redeem at this cafe.", "danger")
            return redirect(url_for("staff_home"))

        card = ensure_loyalty_card(u, cafe)
        if not card.reward_available:
            if is_ajax_request():
                return jsonify({"ok": False, "message": "No reward available yet."}), 400
            flash("No reward available yet.", "warning")
            return redirect(url_for("staff_home"))

        reward_name = settings.reward_name
        if settings.loyalty_type == "tiered_points" and card.unlocked_tier:
            reward_name = card.unlocked_tier.reward_name

        reset_loyalty(card, settings)
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=u.id,
            action="reward_redeemed",
            note=build_action_note(actor.username, f"redeemed {reward_name}", reason_code, reason_note)
        )

        if settings.enable_notifications:
            create_notification(
                u.id,
                cafe.id,
                "Reward redeemed",
                f"Your {reward_name} was redeemed at {cafe.name}."
            )

        message = f"Redeemed {reward_name} for {u.username}."
        if is_ajax_request():
            return jsonify({"ok": True, "message": message})
        flash(message, "success")
        return redirect(url_for("staff_home"))

    @app.get("/staff/search-json")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_search_json():
        cafe = current_cafe()
        settings = ensure_cafe_settings(cafe)
        q = (request.args.get("q") or "").strip()
        normalized_q = normalize_phone(q)

        if len(q) < 2:
            return jsonify([])

        users = (
            User.query.filter(User.is_active == True)  # noqa: E712
            .filter((User.username.ilike(f"{q}%")) | (User.email.ilike(f"{q}%")))
            .order_by(User.username.asc())
            .limit(10)
            .all()
        )
        if normalized_q:
            contacts = UserContact.query.filter(UserContact.phone_search.ilike(f"{normalized_q}%")).limit(10).all()
            for contact in contacts:
                contact_user = db.session.get(User, contact.user_id)
                if contact_user and all(existing.id != contact_user.id for existing in users):
                    users.append(contact_user)

        payload = []
        for u in users:
            contact = get_user_contact(u.id)
            card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()

            if not card and settings.auto_create_card_on_first_scan:
                if settings.loyalty_type == "stamps":
                    current = 0
                    required = settings.stamps_required
                    unit_label = "stamps"
                    reward_name = settings.reward_name
                    reward_available = False
                elif settings.loyalty_type == "points":
                    current = 0
                    required = settings.points_required
                    unit_label = "points"
                    reward_name = settings.reward_name
                    reward_available = False
                else:
                    current = 0
                    next_tier = get_next_tier(0, cafe.id)
                    required = next_tier.points_required if next_tier else 0
                    unit_label = "points"
                    reward_name = next_tier.reward_name if next_tier else settings.reward_name
                    reward_available = False
            elif not card:
                continue
            else:
                progress = get_loyalty_progress(card, settings, cafe.id)
                current = progress["current"]
                required = progress["required"]
                unit_label = progress["unit_label"]
                reward_name = progress["reward_name"]
                reward_available = card.reward_available
            meta = get_customer_meta(cafe.id, u.id)

            payload.append({
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "phone_number": contact.phone_number if contact and contact.phone_number else "",
                "current": current,
                "required": required,
                "unit_label": unit_label,
                "reward_available": reward_available,
                "reward_name": reward_name,
                "loyalty_type": settings.loyalty_type,
                "qr_token": u.qr_token,
                "customer_note": meta.note if meta and meta.note else "",
                "is_flagged": bool(meta.is_flagged) if meta else False,
            })

        return jsonify(payload)

    @app.post("/staff/create-user")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("staff", "manager")
    def staff_create_user():
        require_csrf()
        cafe = current_cafe()
        actor = current_user()

        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        phone_number = (request.form.get("phone_number") or "").strip()

        if not username or not email:
            flash("Username and email are required.", "danger")
            return redirect(url_for("staff_home"))
        blocked = get_blocked_contact(email=email, phone_number=phone_number)
        if blocked:
            flash(blocked_contact_message(blocked), "danger")
            return redirect(url_for("staff_home"))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("staff_home"))
        if User.query.filter_by(email=email).first():
            flash("Email already in use.", "danger")
            return redirect(url_for("staff_home"))

        normalized_phone = normalize_phone(phone_number)
        if normalized_phone and UserContact.query.filter_by(phone_search=normalized_phone).first():
            flash("Phone number already in use.", "danger")
            return redirect(url_for("staff_home"))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(secrets.token_urlsafe(32)),
            pending_email=None,
            email_verified_at=None,
            requires_password_setup=True,
            requires_email_verification=True,
            is_active=True,
            is_global_admin=False,
        )
        db.session.add(user)
        db.session.flush()
        upsert_user_contact(user.id, phone_number)
        ensure_loyalty_card(user, cafe)
        db.session.commit()

        email_sent, email_message, setup_url = send_new_user_setup_email(
            user=user,
            created_by_label=f"{actor.username} from {cafe.name}",
            cafe=cafe,
        )

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=user.id,
            action="customer_created",
            note=f"Staff created customer account for {username}"
        )

        if email_sent:
            flash(f"Created customer account for {username} and emailed them a password setup link.", "success")
        else:
            flash(f"Created customer account for {username}, but email could not be sent. Setup link: {setup_url} ({email_message})", "warning")
        return redirect(url_for("staff_home"))




