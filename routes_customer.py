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


def register_customer_routes(app, ctx):
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
    # Customer pages
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
            if not cafe or not cafe_is_available(cafe):
                continue
            settings = ensure_cafe_settings(cafe)
            progress = get_loyalty_progress(card, settings, cafe.id)
            rows.append((cafe, card, settings, progress))

        return render_template("my_stamps.html", rows=rows)

    @app.get("/account")
    @require_login
    def account():
        u = current_user()
        cafes = cafes_accessible_to_user(u)
        contact = get_user_contact(u.id)
        return render_template("account.html", cafes=cafes, contact=contact)

    @app.post("/account/profile")
    @require_login
    def account_update_profile():
        require_csrf()
        u = current_user()

        username = (request.form.get("username") or "").strip()
        submitted_email = (request.form.get("email") or "").strip().lower()
        phone_number = (request.form.get("phone_number") or "").strip()

        current_email = u.email

        if not username or not submitted_email:
            flash("Username and email are required.", "danger")
            return redirect(url_for("account"))

        existing_username = User.query.filter(User.username == username, User.id != u.id).first()
        if existing_username:
            flash("Username already taken.", "danger")
            return redirect(url_for("account"))

        existing_email = User.query.filter(User.email == submitted_email, User.id != u.id).first()
        if existing_email:
            flash("Email already in use.", "danger")
            return redirect(url_for("account"))
        normalized_phone = normalize_phone(phone_number)
        existing_phone = UserContact.query.filter(UserContact.phone_search == normalized_phone, UserContact.user_id != u.id).first() if normalized_phone else None
        if existing_phone:
            flash("Phone number already in use.", "danger")
            return redirect(url_for("account"))
        blocked = get_blocked_contact(email=submitted_email, phone_number=phone_number)
        if blocked:
            flash(blocked_contact_message(blocked), "danger")
            return redirect(url_for("account"))

        u.username = username
        upsert_user_contact(u.id, phone_number)
        flash_message = "Profile updated."
        flash_level = "success"

        if submitted_email != current_email:
            u.pending_email = submitted_email
            u.requires_email_verification = True
            db.session.commit()
            email_sent, email_message, verify_url = send_email_verification_email(
                user=u,
                email=submitted_email,
                purpose_label="Confirm this new email address to finish updating your account.",
            )
            if email_sent:
                flash_message = f"Profile updated. Verify {submitted_email} from your inbox to finish changing your email."
            else:
                flash_message = f"Profile updated, but the verification email could not be sent. Verify here: {verify_url} ({email_message})"
                flash_level = "warning"
        else:
            u.pending_email = None
            u.requires_email_verification = False
            db.session.commit()

        flash(flash_message, flash_level)
        return redirect(url_for("account"))

    @app.post("/account/password")
    @require_login
    def account_change_password():
        require_csrf()
        u = current_user()

        current_password = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not check_password_hash(u.password_hash, current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("account"))
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "danger")
            return redirect(url_for("account"))
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("account"))

        u.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash("Password changed.", "success")
        return redirect(url_for("account"))

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
        if not cafe or not cafe_is_available(cafe):
            flash("Cafe not found.", "danger")
            return redirect(url_for("select_cafe"))

        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet. Ask staff to scan your QR first.", "danger")
            return redirect(url_for("select_cafe"))

        return redirect(url_for("cafe_home", cafe_slug=cafe.slug))

        if not is_global_admin(u):
            member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            has_card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not member and not has_card:
                flash("You don't have access to that cafe yet. Ask staff to scan your QR first.", "danger")
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

    @app.get("/<cafe_slug>/")
    def cafe_home(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)

        u = current_user()
        if not u:
            settings = ensure_cafe_settings(cafe)
            owner_membership = get_cafe_owner_membership(cafe.id)
            owner_user = db.session.get(User, owner_membership.user_id) if owner_membership else None
            total_customers = LoyaltyCard.query.filter_by(cafe_id=cafe.id).count()
            return render_template(
                "cafe_public_landing.html",
                cafe=cafe,
                settings=settings,
                owner_user=owner_user,
                total_customers=total_customers,
            )
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id

        if is_global_admin(u):
            return render_staff_home_page(cafe)

        member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
        if member and member.role in ("staff", "manager", "owner"):
            return render_staff_home_page(cafe)

        return render_card_page_for_user(u, cafe)

    @app.get("/<cafe_slug>/card")
    @require_login
    def cafe_card(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        return render_card_page_for_user(u, cafe)

    @app.get("/<cafe_slug>/history")
    @require_login
    def cafe_history(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        return render_card_history_page_for_user(u, cafe)

    @app.get("/<cafe_slug>/staff")
    @require_login
    def cafe_staff(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        if not is_global_admin(u):
            member = get_membership(u, cafe)
            if not member or member.role not in ("staff", "manager", "owner"):
                abort(403)
        return render_staff_home_page(cafe)

    @app.get("/<cafe_slug>/manager")
    @require_login
    def cafe_manager_dashboard(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        if not is_global_admin(u):
            member = get_membership(u, cafe)
            if not member or not is_manager_role(member.role):
                abort(403)
        return render_manager_dashboard_page(cafe)

    @app.get("/<cafe_slug>/manager/staff")
    @require_login
    def cafe_manager_staff(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        if not is_global_admin(u):
            member = get_membership(u, cafe)
            if not member or not is_manager_role(member.role):
                abort(403)
        invite_status = (request.args.get("invite_status") or "active").strip().lower()
        return render_manager_staff_page(cafe, invite_status)

    @app.get("/<cafe_slug>/manager/audit")
    @require_login
    def cafe_manager_audit(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        if not is_global_admin(u):
            member = get_membership(u, cafe)
            if not member or not is_manager_role(member.role):
                abort(403)
        action_filter = (request.args.get("action") or "").strip().lower()
        q = (request.args.get("q") or "").strip().lower()
        return render_manager_audit_page(cafe, action_filter, q)

    @app.get("/<cafe_slug>/manager/customers")
    @require_login
    def cafe_manager_customers(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        if not is_global_admin(u):
            member = get_membership(u, cafe)
            if not member or not is_manager_role(member.role):
                abort(403)
        q = (request.args.get("q") or "").strip().lower()
        return render_manager_customers_page(cafe, q)

    @app.get("/<cafe_slug>/manager/customers/<int:user_id>")
    @require_login
    def cafe_manager_customer_profile(cafe_slug: str, user_id: int):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        if not is_global_admin(u):
            member = get_membership(u, cafe)
            if not member or not is_manager_role(member.role):
                abort(403)

        customer = db.session.get(User, user_id)
        if not customer or customer.is_global_admin:
            abort(404)
        return render_manager_customer_profile_page(cafe, customer)

    @app.get("/<cafe_slug>/settings")
    @require_login
    def cafe_slug_settings(cafe_slug: str):
        cafe = Cafe.query.filter_by(slug=cafe_slug).first()
        if not cafe or not cafe_is_available(cafe):
            abort(404)
        u = current_user()
        if not user_can_access_cafe(u, cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        return render_cafe_settings_page(u, cafe)

    @app.get("/open-cafe/<int:cafe_id>")
    @require_login
    def open_cafe(cafe_id: int):
        cafe = db.session.get(Cafe, cafe_id)
        if not cafe or not cafe_is_available(cafe):
            flash("Cafe not found.", "danger")
            return redirect(url_for("select_cafe"))

        if not user_can_access_cafe(current_user(), cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        return redirect(url_for("cafe_home", cafe_slug=cafe.slug))

        u = current_user()
        if not is_global_admin(u):
            member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            has_card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not member and not has_card:
                flash("You don't have access to that cafe yet.", "danger")
                return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id

        if is_global_admin(u):
            return redirect(url_for("staff_home"))

        member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
        if member and member.role in ("staff", "manager"):
            return redirect(url_for("staff_home"))

        return redirect(url_for("card"))

    @app.get("/open-card/<int:cafe_id>")
    @require_login
    def open_card(cafe_id: int):
        cafe = db.session.get(Cafe, cafe_id)
        if not cafe or not cafe_is_available(cafe):
            flash("Cafe not found.", "danger")
            return redirect(url_for("select_cafe"))

        if not user_can_access_cafe(current_user(), cafe):
            flash("You don't have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        return redirect(url_for("cafe_card", cafe_slug=cafe.slug))

        u = current_user()
        if not is_global_admin(u):
            member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            has_card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not member and not has_card:
                flash("You don't have access to that cafe yet.", "danger")
                return redirect(url_for("select_cafe"))

        session["cafe_id"] = cafe.id
        return redirect(url_for("card"))

    @app.get("/card")
    @require_login
    @require_cafe_selected
    def card():
        u = current_user()
        cafe = current_cafe()
        return render_card_page_for_user(u, cafe)

    @app.get("/card/history")
    @require_login
    @require_cafe_selected
    def card_history():
        u = current_user()
        cafe = current_cafe()
        return render_card_history_page_for_user(u, cafe)

    @app.get("/card/status")
    @require_login
    @require_cafe_selected
    def card_status():
        u = current_user()
        cafe = current_cafe()
        settings = ensure_cafe_settings(cafe)
        card = ensure_loyalty_card(u, cafe)
        progress = get_loyalty_progress(card, settings, cafe.id)

        return jsonify({
            "loyalty_type": settings.loyalty_type,
            "current": progress["current"],
            "required": progress["required"],
            "remaining": progress["remaining"],
            "progress": progress["progress"],
            "unit_label": progress["unit_label"],
            "reward_available": card.reward_available,
            "reward_name": progress["reward_name"],
            "stamp_count": card.stamp_count,
            "points_balance": card.points_balance,
            "next_tier_name": progress["next_tier"].reward_name if progress["next_tier"] else None,
            "next_tier_points": progress["next_tier"].points_required if progress["next_tier"] else None,
            "unlocked_tier_name": progress["unlocked_tier"].reward_name if progress["unlocked_tier"] else None,
        })

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





