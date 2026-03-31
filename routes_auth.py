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


def register_auth_routes(app, ctx):
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
    # Home / auth
    # ---------------------------
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/favicon.ico")
    def favicon():
        return send_from_directory(app.root_path, "favicon.ico", mimetype="image/x-icon")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        global_settings = ensure_global_settings()
        if not global_settings.allow_public_registration:
            flash("Public registration is currently disabled.", "warning")
            return redirect(url_for("login"))

        if request.method == "POST":
            require_csrf()

            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            phone_number = (request.form.get("phone_number") or "").strip()
            password = request.form.get("password") or ""

            if not username or not email or not password:
                flash("Please fill in all fields.", "danger")
                return redirect(url_for("register"))
            blocked = get_blocked_contact(email=email, phone_number=phone_number)
            if blocked:
                flash(blocked_contact_message(blocked), "danger")
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
            normalized_phone = normalize_phone(phone_number)
            if normalized_phone and UserContact.query.filter_by(phone_search=normalized_phone).first():
                flash("That phone number is already registered.", "danger")
                return redirect(url_for("register"))

            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                pending_email=None,
                email_verified_at=None,
                requires_password_setup=False,
                requires_email_verification=True,
                is_active=True,
                is_global_admin=False,
            )
            db.session.add(user)
            db.session.flush()
            upsert_user_contact(user.id, phone_number)
            db.session.commit()
            email_sent, email_message, verify_url = send_email_verification_email(
                user=user,
                email=user.email,
                purpose_label=f"Welcome to {global_settings.site_name}. Confirm your email to activate your first login.",
            )
            if email_sent:
                flash("Account created. Check your email to verify your account before logging in.", "success")
            else:
                flash(f"Account created, but verification email could not be sent. Verify here: {verify_url} ({email_message})", "warning")
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

            if not user or not user.is_active:
                flash("Invalid login.", "danger")
                return redirect(url_for("login"))
            blocked = get_user_block(user)
            if blocked:
                flash(blocked_contact_message(blocked), "danger")
                return redirect(url_for("login"))
            if not user.is_global_admin and user.requires_email_verification:
                flash("Verify your email before logging in.", "warning")
                return redirect(url_for("login"))
            if not check_password_hash(user.password_hash, password):
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

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        global_settings = ensure_global_settings()
        reset_url = None

        if request.method == "POST":
            require_csrf()

            email = (request.form.get("email") or "").strip().lower()
            if not email:
                flash("Email is required.", "danger")
                return redirect(url_for("forgot_password"))
            blocked = get_blocked_contact(email=email)
            if blocked:
                flash(blocked_contact_message(blocked), "danger")
                return redirect(url_for("forgot_password"))

            user = User.query.filter_by(email=email).first()
            if not user or not user.is_active:
                flash("If that email exists, a reset link is ready.", "info")
                return render_template(
                    "forgot_password.html",
                    reset_url=None,
                    reset_expiry_hours=max(global_settings.password_reset_expiry_hours, 1),
                )

            active_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).all()
            now = datetime.utcnow()
            for token_row in active_tokens:
                token_row.used_at = now

            reset = PasswordResetToken(
                user_id=user.id,
                expires_at=now + timedelta(hours=max(global_settings.password_reset_expiry_hours, 1)),
            )
            db.session.add(reset)
            db.session.commit()

            reset_url = url_for("reset_password", token=reset.token, _external=True)
            expiry_hours = max(global_settings.password_reset_expiry_hours, 1)
            branding = get_email_branding()
            email_sent, email_message = send_app_email(
                to_email=user.email,
                subject=f"{global_settings.site_name} password reset",
                text_body=(
                    f"Hello {user.username},\n\n"
                    f"Use the link below to reset your password:\n{reset_url}\n\n"
                    f"This link expires in {expiry_hours} hour(s).\n"
                ),
                html_body=render_template(
                    "emails/password_reset_email.html",
                    site_name=global_settings.site_name,
                    username=user.username,
                    reset_url=reset_url,
                    expiry_hours=expiry_hours,
                    **branding,
                ),
            )
            if email_sent:
                flash("Password reset email sent.", "success")
                reset_url = None
            else:
                flash(f"Reset link generated, but email could not be sent. {email_message}", "warning")

        return render_template(
            "forgot_password.html",
            reset_url=reset_url,
            reset_expiry_hours=max(global_settings.password_reset_expiry_hours, 1),
        )

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token: str):
        reset = get_valid_password_reset(token)
        if not reset:
            flash("That password reset link is invalid or expired.", "danger")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            require_csrf()

            password = request.form.get("password") or ""
            confirm_password = request.form.get("confirm_password") or ""

            if len(password) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return redirect(url_for("reset_password", token=token))
            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return redirect(url_for("reset_password", token=token))

            user = db.session.get(User, reset.user_id)
            if not user or not user.is_active:
                flash("Account not available for password reset.", "danger")
                return redirect(url_for("forgot_password"))

            user.password_hash = generate_password_hash(password)
            user.requires_password_setup = False
            if not user.email_verified_at:
                user.email_verified_at = datetime.utcnow()
            user.requires_email_verification = False

            now = datetime.utcnow()
            open_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).all()
            for token_row in open_tokens:
                token_row.used_at = now

            db.session.commit()

            flash("Password updated. You can log in now.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

    @app.get("/verify-email/<token>")
    def verify_email(token: str):
        verification = get_valid_email_verification(token)
        if not verification:
            flash("That email verification link is invalid or expired.", "danger")
            return redirect(url_for("login"))

        user = db.session.get(User, verification.user_id)
        if not user or not user.is_active:
            flash("Account not available for verification.", "danger")
            return redirect(url_for("login"))

        if verification.email != user.email:
            existing = User.query.filter(User.email == verification.email, User.id != user.id).first()
            if existing:
                flash("That email is already in use.", "danger")
                return redirect(url_for("account"))
            user.email = verification.email
            user.pending_email = None
            create_notification(
                user.id,
                None,
                "Email Updated",
                f"Your email address is now {verification.email}."
            )
            success_redirect = url_for("account")
            success_message = "Your new email address has been verified."
        else:
            create_notification(
                user.id,
                None,
                "Email Verified",
                "Your email address is verified and ready to use."
            )
            success_redirect = url_for("login")
            success_message = "Email verified. You can log in now."

        verification.used_at = datetime.utcnow()
        user.email_verified_at = datetime.utcnow()
        user.requires_email_verification = False
        db.session.commit()

        flash(success_message, "success")
        return redirect(success_redirect)

    @app.post("/logout")
    def logout():
        require_csrf()
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("index"))

    # ---------------------------
    # Invite acceptance
    # ---------------------------
    @app.route("/invite/<token>", methods=["GET", "POST"])
    def invite_accept(token: str):
        invite = StaffInvite.query.filter_by(token=token, is_active=True).first()
        if not invite:
            flash("Invite not found or no longer active.", "danger")
            return redirect(url_for("login"))

        if invite.expires_at and invite.expires_at < datetime.utcnow():
            invite.is_active = False
            db.session.commit()
            flash("This invite has expired.", "danger")
            return redirect(url_for("login"))

        cafe = db.session.get(Cafe, invite.cafe_id)
        if not cafe or not cafe_is_available(cafe):
            flash("This cafe is not available.", "danger")
            return redirect(url_for("login"))

        if request.method == "POST":
            require_csrf()

            email = (request.form.get("email") or "").strip().lower()
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            if email != invite.email:
                flash("Email must match the invite email.", "danger")
                return redirect(url_for("invite_accept", token=token))
            blocked = get_blocked_contact(email=email)
            if blocked:
                flash(blocked_contact_message(blocked), "danger")
                return redirect(url_for("invite_accept", token=token))

            user = User.query.filter_by(email=email).first()

            if not user:
                if not username or len(password) < 8:
                    flash("New account requires username and 8+ character password.", "danger")
                    return redirect(url_for("invite_accept", token=token))
                if User.query.filter_by(username=username).first():
                    flash("Username already taken.", "danger")
                    return redirect(url_for("invite_accept", token=token))

                user = User(
                    username=username,
                    email=email,
                    password_hash=generate_password_hash(password),
                    pending_email=None,
                    email_verified_at=datetime.utcnow(),
                    requires_password_setup=False,
                    requires_email_verification=False,
                    is_active=True,
                    is_global_admin=False,
                )
                db.session.add(user)
                db.session.flush()

            mem = CafeMember.query.filter_by(user_id=user.id, cafe_id=cafe.id).first()
            if not mem:
                mem = CafeMember(
                    user_id=user.id,
                    cafe_id=cafe.id,
                    role=invite.role,
                    is_active=True,
                )
                db.session.add(mem)
            else:
                mem.role = invite.role
                mem.is_active = True

            invite.is_active = False
            invite.accepted_at = datetime.utcnow()

            db.session.commit()

            log_activity(
                cafe_id=cafe.id,
                actor_user_id=user.id,
                target_user_id=user.id,
                action="invite_accepted",
                note=f"Accepted invite as {invite.role}"
            )

            flash(f"You’ve joined {cafe.name} as {invite.role}.", "success")
            return redirect(url_for("login"))

        return render_template("invite_accept.html", invite=invite, cafe=cafe)

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




