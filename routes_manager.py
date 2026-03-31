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


def register_manager_routes(app, ctx):
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
    # Manager dashboard / staff / settings
    # ---------------------------
    @app.get("/manager")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_dashboard():
        cafe = current_cafe()
        return render_manager_dashboard_page(cafe)

    @app.get("/manager/audit")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_audit():
        cafe = current_cafe()
        action_filter = (request.args.get("action") or "").strip().lower()
        q = (request.args.get("q") or "").strip().lower()
        return render_manager_audit_page(cafe, action_filter, q)

    @app.post("/manager/reset-loyalty")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_reset_loyalty():
        require_csrf()
        cafe = current_cafe()
        actor = current_user()
        settings = ensure_cafe_settings(cafe)

        user_id = request.form.get("user_id")
        if not user_id or not user_id.isdigit():
            flash("Invalid user.", "danger")
            return redirect_cafe_manager_dashboard(cafe)

        u = db.session.get(User, int(user_id))
        if not u or u.is_global_admin:
            flash("User not found.", "danger")
            return redirect_cafe_manager_dashboard(cafe)

        card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
        if not card:
            flash("No loyalty card for this user at this cafe.", "warning")
            return redirect_cafe_manager_dashboard(cafe)

        reset_loyalty(card, settings)
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=u.id,
            action="loyalty_reset",
            note="Manager reset loyalty"
        )

        flash(f"Reset loyalty for {u.username}.", "success")
        return redirect_cafe_manager_dashboard(cafe)

    @app.post("/manager/customer-note")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_customer_note():
        require_csrf()
        cafe = current_cafe()
        actor = current_user()
        redirect_to = (request.form.get("redirect_to") or "dashboard").strip().lower()

        user_id = (request.form.get("user_id") or "").strip()
        if not user_id.isdigit():
            flash("Invalid customer.", "danger")
            return redirect_cafe_manager_dashboard(cafe)

        u = db.session.get(User, int(user_id))
        if not u or u.is_global_admin:
            flash("Customer not found.", "danger")
            return redirect_cafe_manager_dashboard(cafe)

        note = (request.form.get("note") or "").strip()
        is_flagged = request.form.get("is_flagged") == "on"
        upsert_customer_meta(cafe.id, u.id, note=note, is_flagged=is_flagged, updated_by_user_id=actor.id)
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=actor.id,
            target_user_id=u.id,
            action="customer_note_updated",
            note=f"Updated customer note (flagged: {'yes' if is_flagged else 'no'})"
        )

        flash(f"Updated note for {u.username}.", "success")
        if redirect_to == "profile":
            return redirect(url_for("cafe_manager_customer_profile", cafe_slug=cafe.slug, user_id=u.id))
        return redirect_cafe_manager_dashboard(cafe)

    @app.post("/manager/customer-moderation")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_customer_moderation():
        require_csrf()
        cafe = current_cafe()
        actor = current_user()

        user_id = (request.form.get("user_id") or "").strip()
        if not user_id.isdigit():
            flash("Invalid customer.", "danger")
            return redirect_cafe_manager_customers(cafe)

        customer = db.session.get(User, int(user_id))
        if not customer or customer.is_global_admin:
            flash("Customer not found.", "danger")
            return redirect_cafe_manager_customers(cafe)

        action = (request.form.get("action") or "").strip().lower()
        reason = (request.form.get("reason") or "").strip()
        note = (request.form.get("note") or "").strip()

        if action == "suspend":
            update_customer_suspension(
                cafe.id,
                customer.id,
                actor_user_id=actor.id,
                is_suspended=True,
                reason=reason or "manager_action",
                note=note,
            )
            db.session.commit()
            log_activity(
                cafe_id=cafe.id,
                actor_user_id=actor.id,
                target_user_id=customer.id,
                action="customer_suspended",
                note=f"Suspended customer. Reason: {reason or 'manager_action'}{f' | {note}' if note else ''}"
            )
            flash(f"Suspended {customer.username} at {cafe.name}.", "success")
        elif action == "reactivate":
            update_customer_suspension(
                cafe.id,
                customer.id,
                actor_user_id=actor.id,
                is_suspended=False,
                reason=None,
                note=None,
            )
            db.session.commit()
            log_activity(
                cafe_id=cafe.id,
                actor_user_id=actor.id,
                target_user_id=customer.id,
                action="customer_reactivated",
                note="Reactivated customer"
            )
            flash(f"Reactivated {customer.username}.", "success")
        else:
            flash("Unknown customer moderation action.", "danger")

        return redirect(url_for("cafe_manager_customer_profile", cafe_slug=cafe.slug, user_id=customer.id))

    @app.get("/manager/staff")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_staff():
        cafe = current_cafe()
        invite_status = (request.args.get("invite_status") or "active").strip().lower()
        return render_manager_staff_page(cafe, invite_status)

    @app.get("/manager/customers")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_customers():
        cafe = current_cafe()
        q = (request.args.get("q") or "").strip().lower()
        return render_manager_customers_page(cafe, q)

    @app.get("/manager/customers/<int:user_id>")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_customer_profile(user_id: int):
        cafe = current_cafe()
        customer = db.session.get(User, user_id)
        if not customer or customer.is_global_admin:
            abort(404)
        return render_manager_customer_profile_page(cafe, customer)

    @app.post("/manager/staff/add")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_staff_add():
        require_csrf()
        cafe = current_cafe()

        identifier = (request.form.get("identifier") or "").strip()
        normalized_identifier = normalize_phone(identifier)
        role = (request.form.get("role") or "staff").strip().lower()
        if role not in ("staff", "manager"):
            role = "staff"

        if not identifier:
            flash("Enter a username or email.", "danger")
            return redirect_cafe_manager_staff(cafe)

        u = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()
        if not u and normalized_identifier:
            contact = UserContact.query.filter_by(phone_search=normalized_identifier).first()
            u = db.session.get(User, contact.user_id) if contact else None

        if not u:
            flash("User not found.", "danger")
            return redirect_cafe_manager_staff(cafe)
        if u.is_global_admin:
            flash("Cannot assign global admins.", "danger")
            return redirect_cafe_manager_staff(cafe)

        mem = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
        if not mem:
            mem = CafeMember(user_id=u.id, cafe_id=cafe.id, role=role, is_active=True)
            db.session.add(mem)
        else:
            if mem.role == "owner":
                flash("Cafe owners cannot be changed by another manager.", "danger")
                return redirect_cafe_manager_staff(cafe)
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
        return redirect_cafe_manager_staff(cafe)

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
            return redirect_cafe_manager_staff(cafe)

        mem = db.session.get(CafeMember, int(member_id))
        if not mem or mem.cafe_id != cafe.id:
            flash("Member not found.", "danger")
            return redirect_cafe_manager_staff(cafe)

        u = db.session.get(User, mem.user_id)
        if not u or u.is_global_admin:
            flash("Cannot edit this user.", "danger")
            return redirect_cafe_manager_staff(cafe)
        if mem.role == "owner":
            flash("Cafe owners cannot be changed by another manager.", "danger")
            return redirect_cafe_manager_staff(cafe)

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
            return redirect_cafe_manager_staff(cafe)

        if action == "set_role":
            role = (request.form.get("role") or "").strip().lower()
            if role not in ("staff", "manager"):
                flash("Invalid role.", "danger")
                return redirect_cafe_manager_staff(cafe)
            assign_membership_role(mem, role)
            db.session.commit()
            flash(f"Updated {u.username} to {role}.", "success")
            return redirect_cafe_manager_staff(cafe)

        flash("Unknown action.", "danger")
        return redirect_cafe_manager_staff(cafe)

    @app.post("/manager/staff/set-password")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_staff_set_password():
        require_csrf()
        cafe = current_cafe()
        settings = ensure_cafe_settings(cafe)

        if not settings.staff_can_change_password:
            flash("Managers are not allowed to change staff passwords at this cafe.", "danger")
            return redirect_cafe_manager_staff(cafe)

        member_id = request.form.get("member_id", "")

        if not member_id.isdigit():
            flash("Invalid member.", "danger")
            return redirect_cafe_manager_staff(cafe)

        mem = db.session.get(CafeMember, int(member_id))
        if not mem or mem.cafe_id != cafe.id or not mem.is_active:
            flash("Member not found.", "danger")
            return redirect_cafe_manager_staff(cafe)

        target_user = db.session.get(User, mem.user_id)
        if not target_user or target_user.is_global_admin:
            flash("Cannot change this user.", "danger")
            return redirect_cafe_manager_staff(cafe)

        target_user.password_hash = generate_password_hash(secrets.token_urlsafe(32))
        target_user.requires_password_setup = True
        target_user.requires_email_verification = True
        db.session.commit()

        email_sent, email_message, setup_url = send_new_user_setup_email(
            user=target_user,
            created_by_label=f"{current_user().username} from {cafe.name}",
            cafe=cafe,
        )

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=current_user().id,
            target_user_id=target_user.id,
            action="password_changed",
            note="Manager forced password reset"
        )

        if email_sent:
            flash(f"Password setup email sent to {target_user.username}.", "success")
        else:
            flash(f"Password setup email could not be sent. Setup link: {setup_url} ({email_message})", "warning")
        return redirect_cafe_manager_staff(cafe)

    @app.post("/manager/invites/create")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_create_invite():
        require_csrf()
        cafe = current_cafe()
        global_settings = ensure_global_settings()
        settings = ensure_cafe_settings(cafe)

        if not global_settings.allow_global_manager_invites:
            flash("Manager invites are disabled globally.", "danger")
            return redirect_cafe_manager_staff(cafe)

        if not settings.allow_manager_invites:
            flash("Manager invites are disabled for this cafe.", "danger")
            return redirect_cafe_manager_staff(cafe)

        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or settings.default_invite_role).strip().lower()
        if role not in ("staff", "manager"):
            role = settings.default_invite_role

        if not email:
            flash("Email is required.", "danger")
            return redirect_cafe_manager_staff(cafe)
        blocked = get_blocked_contact(email=email)
        if blocked:
            flash(blocked_contact_message(blocked), "danger")
            return redirect_cafe_manager_staff(cafe)

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            member = CafeMember.query.filter_by(user_id=existing_user.id, cafe_id=cafe.id).first()
            if not member:
                member = CafeMember(
                    user_id=existing_user.id,
                    cafe_id=cafe.id,
                    role=role,
                    is_active=True,
                )
                db.session.add(member)
            else:
                if member.role == "owner":
                    flash("Cafe owners cannot be changed by another manager.", "danger")
                    return redirect_cafe_manager_staff(cafe)
                member.role = role
                member.is_active = True

            db.session.commit()

            cafe_url = url_for("cafe_home", cafe_slug=cafe.slug, _external=True)
            branding = get_email_branding(cafe)
            email_sent, email_message = send_app_email(
                to_email=email,
                subject=f"You’ve been added to {cafe.name}",
                text_body=(
                    f"Hello {existing_user.username},\n\n"
                    f"You have been added to {cafe.name} as {role}.\n\n"
                    f"Open your cafe here:\n{cafe_url}\n"
                ),
                html_body=render_template(
                    "emails/added_to_cafe_email.html",
                    site_name=global_settings.site_name,
                    username=existing_user.username,
                    cafe_name=cafe.name,
                    role=role,
                    cafe_url=cafe_url,
                    **branding,
                ),
            )

            log_activity(
                cafe_id=cafe.id,
                actor_user_id=current_user().id,
                target_user_id=existing_user.id,
                action="existing_user_added_to_cafe",
                note=f"Existing user {email} added to cafe as {role}"
            )

            if email_sent:
                flash("Existing user added to cafe and emailed.", "success")
            else:
                flash(f"Existing user added to cafe, but email could not be sent. {email_message}", "warning")
            return redirect_cafe_manager_staff(cafe)

        invite = StaffInvite(
            cafe_id=cafe.id,
            created_by_user_id=current_user().id,
            email=email,
            role=role,
            expires_at=datetime.utcnow() + timedelta(days=max(settings.invite_expiry_days, 1)),
            is_active=True,
        )
        db.session.add(invite)
        db.session.commit()

        email_sent, email_message, invite_url = send_staff_invite_email(
            invite=invite,
            cafe=cafe,
            site_name=ensure_global_settings().site_name,
        )

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=current_user().id,
            target_user_id=current_user().id,
            action="invite_created",
            note=f"Invite created for {email} as {role}"
        )

        if email_sent:
            flash("Invite created and emailed.", "success")
        else:
            flash(f"Invite created, but email could not be sent. {email_message}", "warning")
        return redirect_cafe_manager_staff(cafe)

    @app.post("/manager/invites/revoke")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_revoke_invite():
        require_csrf()
        cafe = current_cafe()

        invite_id = (request.form.get("invite_id") or "").strip()
        if not invite_id.isdigit():
            flash("Invalid invite.", "danger")
            return redirect_cafe_manager_staff(cafe)

        invite = db.session.get(StaffInvite, int(invite_id))
        if not invite or invite.cafe_id != cafe.id:
            flash("Invite not found.", "danger")
            return redirect_cafe_manager_staff(cafe)

        if not invite.is_active or invite.accepted_at:
            flash("Invite is no longer active.", "warning")
            return redirect_cafe_manager_staff(cafe)

        invite.is_active = False
        db.session.commit()

        log_activity(
            cafe_id=cafe.id,
            actor_user_id=current_user().id,
            target_user_id=current_user().id,
            action="invite_revoked",
            note=f"Invite revoked for {invite.email}"
        )

        flash("Invite revoked.", "success")
        return redirect_cafe_manager_staff(cafe)

    @app.post("/manager/invites/resend")
    @require_login
    @require_cafe_selected
    @require_role_in_cafe("manager")
    def manager_resend_invite():
        require_csrf()
        cafe = current_cafe()

        invite_id = (request.form.get("invite_id") or "").strip()
        if not invite_id.isdigit():
            flash("Invalid invite.", "danger")
            return redirect_cafe_manager_staff(cafe)

        invite = db.session.get(StaffInvite, int(invite_id))
        if not invite or invite.cafe_id != cafe.id:
            flash("Invite not found.", "danger")
            return redirect_cafe_manager_staff(cafe)
        if invite.accepted_at:
            flash("This invite has already been accepted.", "warning")
            return redirect_cafe_manager_staff(cafe, invite_status="accepted")
        if not invite.is_active:
            flash("This invite is no longer active.", "warning")
            return redirect_cafe_manager_staff(cafe)
        if invite.expires_at and invite.expires_at < datetime.utcnow():
            flash("This invite has expired.", "warning")
            return redirect_cafe_manager_staff(cafe, invite_status="expired")

        email_sent, email_message, invite_url = send_staff_invite_email(
            invite=invite,
            cafe=cafe,
            site_name=ensure_global_settings().site_name,
        )
        if email_sent:
            flash("Invite email resent.", "success")
        else:
            flash(f"Invite email could not be sent. Invite link: {invite_url} ({email_message})", "warning")
        return redirect_cafe_manager_staff(cafe)

    # ---------------------------
    # Settings
    # ---------------------------
    @app.get("/settings")
    @require_login
    @require_cafe_selected
    def cafe_settings():
        u = current_user()
        cafe = current_cafe()
        return render_cafe_settings_page(u, cafe)

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
        global_settings = ensure_global_settings()

        if request.form.get("action") == "reset_defaults":
            fresh_settings = build_default_cafe_settings(cafe.id, global_settings)
            settings.stamps_required = fresh_settings.stamps_required
            settings.points_required = fresh_settings.points_required
            settings.points_per_purchase = fresh_settings.points_per_purchase
            settings.reward_name = fresh_settings.reward_name
            settings.welcome_message = fresh_settings.welcome_message
            settings.invite_expiry_days = fresh_settings.invite_expiry_days
            settings.allow_manager_invites = fresh_settings.allow_manager_invites
            db.session.commit()
            log_activity(
                cafe_id=cafe.id,
                actor_user_id=u.id,
                target_user_id=u.id,
                action="settings_updated",
                note="Cafe settings reset to global defaults"
            )
            flash("Cafe settings reset to global defaults.", "success")
            return redirect_cafe_settings_page(cafe)

        cafe.logo_url = (request.form.get("logo_url") or "").strip() or None
        cafe.accent_color = (request.form.get("accent_color") or cafe.accent_color).strip()
        cafe.secondary_color = (request.form.get("secondary_color") or cafe.secondary_color).strip()

        theme_mode = (request.form.get("theme_mode") or cafe.theme_mode).strip().lower()
        if theme_mode in ("light", "dark", "coffee", "modern"):
            cafe.theme_mode = theme_mode

        card_style = (request.form.get("card_style") or cafe.card_style).strip().lower()
        if card_style in ("rounded", "minimal", "bold"):
            cafe.card_style = card_style

        loyalty_type = (request.form.get("loyalty_type") or settings.loyalty_type).strip().lower()
        if loyalty_type in ("stamps", "points"):
            settings.loyalty_type = loyalty_type

        stamps_required = (request.form.get("stamps_required") or "").strip()
        points_required = (request.form.get("points_required") or "").strip()
        points_per_purchase = (request.form.get("points_per_purchase") or "").strip()

        if stamps_required.isdigit():
            settings.stamps_required = max(int(stamps_required), 1)
        if points_required.isdigit():
            settings.points_required = max(int(points_required), 1)
        if points_per_purchase.isdigit():
            settings.points_per_purchase = max(int(points_per_purchase), 1)

        reward_name = (request.form.get("reward_name") or "").strip()
        if reward_name:
            settings.reward_name = reward_name

        welcome_message = (request.form.get("welcome_message") or "").strip()
        if welcome_message:
            settings.welcome_message = welcome_message

        cafe.public_location = (request.form.get("public_location") or "").strip() or None
        cafe.public_opening_hours = (request.form.get("public_opening_hours") or "").strip() or None
        cafe.public_join_instructions = (request.form.get("public_join_instructions") or "").strip() or None

        settings.show_qr_label = request.form.get("show_qr_label") == "on"
        settings.show_stamp_numbers = request.form.get("show_stamp_numbers") == "on"
        settings.show_progress_bar = request.form.get("show_progress_bar") == "on"
        settings.show_reward_badge = request.form.get("show_reward_badge") == "on"

        settings.staff_can_scan = request.form.get("staff_can_scan") == "on"
        settings.staff_can_add_stamp = request.form.get("staff_can_add_stamp") == "on"
        settings.staff_can_redeem = request.form.get("staff_can_redeem") == "on"
        settings.staff_can_reset_loyalty = request.form.get("staff_can_reset_loyalty") == "on"
        settings.staff_can_change_password = request.form.get("staff_can_change_password") == "on"

        settings.allow_multi_cafe_cards = request.form.get("allow_multi_cafe_cards") == "on"
        settings.auto_create_card_on_first_scan = request.form.get("auto_create_card_on_first_scan") == "on"
        settings.show_customer_history = request.form.get("show_customer_history") == "on"
        settings.enable_notifications = request.form.get("enable_notifications") == "on"

        invite_expiry_days = (request.form.get("invite_expiry_days") or "").strip()
        if invite_expiry_days.isdigit():
            settings.invite_expiry_days = max(int(invite_expiry_days), 1)

        settings.allow_manager_invites = request.form.get("allow_manager_invites") == "on"

        default_invite_role = (request.form.get("default_invite_role") or settings.default_invite_role).strip().lower()
        if default_invite_role in ("staff", "manager"):
            settings.default_invite_role = default_invite_role

        db.session.commit()
        log_activity(
            cafe_id=cafe.id,
            actor_user_id=u.id,
            target_user_id=u.id,
            action="settings_updated",
            note="Cafe settings updated"
        )
        flash("Settings updated.", "success")
        return redirect_cafe_settings_page(cafe)

    @app.post("/settings/tiers/add")
    @require_login
    @require_cafe_selected
    def add_reward_tier():
        require_csrf()
        u = current_user()
        cafe = current_cafe()

        if not is_global_admin(u):
            m = get_membership(u, cafe)
            if not m or m.role != "manager":
                abort(403)

        points_required = (request.form.get("points_required") or "").strip()
        reward_name = (request.form.get("reward_name") or "").strip()

        if not points_required.isdigit() or int(points_required) < 1:
            flash("Points required must be a positive number.", "danger")
            return redirect_cafe_settings_page(cafe)
        if not reward_name:
            flash("Reward name is required.", "danger")
            return redirect_cafe_settings_page(cafe)

        existing = RewardTier.query.filter_by(cafe_id=cafe.id, points_required=int(points_required)).first()
        if existing:
            existing.reward_name = reward_name
            existing.is_active = True
        else:
            db.session.add(RewardTier(
                cafe_id=cafe.id,
                points_required=int(points_required),
                reward_name=reward_name,
                is_active=True
            ))

        db.session.commit()
        flash("Reward tier saved.", "success")
        return redirect_cafe_settings_page(cafe)

    @app.post("/settings/tiers/delete")
    @require_login
    @require_cafe_selected
    def delete_reward_tier():
        require_csrf()
        u = current_user()
        cafe = current_cafe()

        if not is_global_admin(u):
            m = get_membership(u, cafe)
            if not m or m.role != "manager":
                abort(403)

        tier_id = request.form.get("tier_id", "")
        if not tier_id.isdigit():
            flash("Invalid tier.", "danger")
            return redirect_cafe_settings_page(cafe)

        tier = db.session.get(RewardTier, int(tier_id))
        if not tier or tier.cafe_id != cafe.id:
            flash("Tier not found.", "danger")
            return redirect_cafe_settings_page(cafe)

        db.session.delete(tier)
        db.session.commit()
        flash("Reward tier deleted.", "success")
        return redirect_cafe_settings_page(cafe)




