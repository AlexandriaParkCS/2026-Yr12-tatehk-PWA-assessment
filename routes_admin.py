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


def register_admin_routes(app, ctx):
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
        global_settings = ensure_global_settings()

        cafe_name = (request.form.get("cafe_name") or "").strip()
        slug = (request.form.get("slug") or "").strip().lower()
        manager_email = (request.form.get("manager_email") or "").strip().lower()
        manager_username = (request.form.get("manager_username") or "").strip()
        new_manager_created = False
        new_manager_user = None

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

        db.session.add(build_default_cafe_settings(cafe.id, global_settings))

        if manager_email:
            blocked = get_blocked_contact(email=manager_email)
            if blocked:
                flash(blocked_contact_message(blocked), "danger")
                db.session.rollback()
                return redirect(url_for("admin_create_cafe"))
            manager_user = User.query.filter_by(email=manager_email).first()

            if not manager_user:
                if not manager_username:
                    flash("To create a new manager, provide a username.", "danger")
                    db.session.rollback()
                    return redirect(url_for("admin_create_cafe"))

                if User.query.filter_by(username=manager_username).first():
                    flash("Manager username already taken.", "danger")
                    db.session.rollback()
                    return redirect(url_for("admin_create_cafe"))

                manager_user = User(
                    username=manager_username,
                    email=manager_email,
                    password_hash=generate_password_hash(secrets.token_urlsafe(32)),
                    pending_email=None,
                    email_verified_at=None,
                    requires_password_setup=True,
                    requires_email_verification=True,
                    is_active=True,
                    is_global_admin=False,
                )
                db.session.add(manager_user)
                db.session.flush()
                new_manager_created = True
                new_manager_user = manager_user

            existing = CafeMember.query.filter_by(user_id=manager_user.id, cafe_id=cafe.id).first()
            if not existing:
                db.session.add(CafeMember(
                    user_id=manager_user.id,
                    cafe_id=cafe.id,
                    role="owner",
                    is_active=True
                ))
            else:
                assign_membership_role(existing, "owner")

        db.session.commit()
        if new_manager_created and new_manager_user:
            email_sent, email_message, setup_url = send_new_user_setup_email(
                user=new_manager_user,
                created_by_label=f"An admin from {ensure_global_settings().site_name}",
                cafe=cafe,
            )
            if email_sent:
                flash(f"Created cafe '{cafe.name}' and sent manager onboarding email.", "success")
            else:
                flash(f"Created cafe '{cafe.name}', but manager onboarding email could not be sent. Setup link: {setup_url} ({email_message})", "warning")
        else:
            flash(f"Created cafe '{cafe.name}'.", "success")
        return redirect(url_for("select_cafe"))

    @app.route("/admin/settings", methods=["GET", "POST"])
    @require_login
    @require_global_admin
    def admin_global_settings():
        settings = ensure_global_settings()
        email_settings = ensure_email_settings()
        blocked_contacts = BlockedContact.query.order_by(BlockedContact.created_at.desc()).all()

        if request.method == "POST":
            require_csrf()

            site_name = (request.form.get("site_name") or "").strip()
            if site_name:
                settings.site_name = site_name

            password_reset_expiry_hours = (request.form.get("password_reset_expiry_hours") or "").strip()
            if password_reset_expiry_hours.isdigit():
                settings.password_reset_expiry_hours = max(int(password_reset_expiry_hours), 1)

            default_stamps_required = (request.form.get("default_stamps_required") or "").strip()
            if default_stamps_required.isdigit():
                settings.default_stamps_required = max(int(default_stamps_required), 1)

            default_points_required = (request.form.get("default_points_required") or "").strip()
            if default_points_required.isdigit():
                settings.default_points_required = max(int(default_points_required), 1)

            default_points_per_purchase = (request.form.get("default_points_per_purchase") or "").strip()
            if default_points_per_purchase.isdigit():
                settings.default_points_per_purchase = max(int(default_points_per_purchase), 1)

            default_invite_expiry_days = (request.form.get("default_invite_expiry_days") or "").strip()
            if default_invite_expiry_days.isdigit():
                settings.default_invite_expiry_days = max(int(default_invite_expiry_days), 1)

            default_reward_name = (request.form.get("default_reward_name") or "").strip()
            if default_reward_name:
                settings.default_reward_name = default_reward_name

            default_welcome_message = (request.form.get("default_welcome_message") or "").strip()
            if default_welcome_message:
                settings.default_welcome_message = default_welcome_message

            settings.allow_public_registration = request.form.get("allow_public_registration") == "on"
            settings.allow_global_manager_invites = request.form.get("allow_global_manager_invites") == "on"
            settings.default_allow_manager_invites = request.form.get("default_allow_manager_invites") == "on"

            smtp_port = (request.form.get("smtp_port") or "").strip()
            if smtp_port.isdigit():
                email_settings.smtp_port = max(int(smtp_port), 1)

            email_settings.smtp_host = (request.form.get("smtp_host") or "").strip() or None
            email_settings.smtp_username = (request.form.get("smtp_username") or "").strip() or None

            smtp_password = request.form.get("smtp_password")
            if smtp_password is not None and smtp_password != "":
                email_settings.smtp_password = smtp_password

            email_settings.from_email = (request.form.get("from_email") or "").strip() or None
            from_name = (request.form.get("from_name") or "").strip()
            if from_name:
                email_settings.from_name = from_name

            email_settings.is_enabled = request.form.get("email_is_enabled") == "on"
            email_settings.use_tls = request.form.get("email_use_tls") == "on"

            db.session.commit()
            flash("Global settings updated.", "success")
            return redirect(url_for("admin_global_settings"))

        return render_template("admin_global_settings.html", settings=settings, email_settings=email_settings, blocked_contacts=blocked_contacts)

    @app.post("/admin/settings/blocked-contacts/add")
    @require_login
    @require_global_admin
    def admin_add_blocked_contact():
        require_csrf()

        block_type = (request.form.get("block_type") or "").strip().lower()
        raw_value = (request.form.get("raw_value") or "").strip()
        note = (request.form.get("note") or "").strip()

        if block_type not in ("email", "phone"):
            flash("Choose email or phone.", "danger")
            return redirect(url_for("admin_global_settings"))
        if not raw_value:
            flash("A value is required.", "danger")
            return redirect(url_for("admin_global_settings"))

        normalized_value = normalize_email(raw_value) if block_type == "email" else normalize_phone(raw_value)
        if not normalized_value:
            flash("Enter a valid value.", "danger")
            return redirect(url_for("admin_global_settings"))

        existing = BlockedContact.query.filter_by(block_type=block_type, normalized_value=normalized_value).first()
        if existing:
            flash("That contact is already blocked.", "warning")
            return redirect(url_for("admin_global_settings"))

        db.session.add(BlockedContact(
            block_type=block_type,
            raw_value=raw_value,
            normalized_value=normalized_value,
            note=note or None,
        ))
        db.session.commit()
        flash("Blocked contact added.", "success")
        return redirect(url_for("admin_global_settings"))

    @app.post("/admin/settings/blocked-contacts/delete")
    @require_login
    @require_global_admin
    def admin_delete_blocked_contact():
        require_csrf()

        blocked_id = (request.form.get("blocked_id") or "").strip()
        if not blocked_id.isdigit():
            flash("Invalid blocked contact.", "danger")
            return redirect(url_for("admin_global_settings"))

        blocked = db.session.get(BlockedContact, int(blocked_id))
        if not blocked:
            flash("Blocked contact not found.", "danger")
            return redirect(url_for("admin_global_settings"))

        db.session.delete(blocked)
        db.session.commit()
        flash("Blocked contact removed.", "success")
        return redirect(url_for("admin_global_settings"))

    @app.get("/admin/cafes")
    @require_login
    @require_global_admin
    def admin_cafes():
        q = (request.args.get("q") or "").strip().lower()
        cafes = Cafe.query.order_by(Cafe.created_at.desc()).all()
        rows = []
        for cafe in cafes:
            haystack = f"{cafe.name} {cafe.slug}".lower()
            if q and q not in haystack:
                continue
            manager_count = CafeMember.query.filter_by(cafe_id=cafe.id, role="manager", is_active=True).count()
            member_count = CafeMember.query.filter_by(cafe_id=cafe.id, is_active=True).count()
            customer_count = LoyaltyCard.query.filter_by(cafe_id=cafe.id).count()
            owner_membership = get_cafe_owner_membership(cafe.id)
            owner_user = db.session.get(User, owner_membership.user_id) if owner_membership else None
            manager_options = (
                db.session.query(CafeMember, User)
                .join(User, User.id == CafeMember.user_id)
                .filter(CafeMember.cafe_id == cafe.id, CafeMember.is_active == True)  # noqa: E712
                .filter(CafeMember.role.in_(("owner", "manager")))
                .order_by(User.username.asc())
                .all()
            )
            rows.append((cafe, manager_count + (1 if owner_membership else 0), member_count, customer_count, owner_user, manager_options))
        return render_template("admin_cafes.html", rows=rows, q=q)

    @app.post("/admin/cafes/<int:cafe_id>/update")
    @require_login
    @require_global_admin
    def admin_cafe_update(cafe_id: int):
        require_csrf()
        cafe = db.session.get(Cafe, cafe_id)
        if not cafe:
            abort(404)

        action = (request.form.get("action") or "").strip()
        if action == "save":
            name = (request.form.get("name") or "").strip()
            slug = (request.form.get("slug") or "").strip().lower()
            if not name or not slug:
                flash("Cafe name and slug are required.", "danger")
                return redirect(url_for("admin_cafes"))
            existing = Cafe.query.filter(Cafe.slug == slug, Cafe.id != cafe.id).first()
            if existing:
                flash("Slug already used by another cafe.", "danger")
                return redirect(url_for("admin_cafes"))
            cafe.name = name
            cafe.slug = slug
            db.session.commit()
            flash(f"Updated {cafe.name}.", "success")
            return redirect(url_for("admin_cafes"))

        if action == "disable":
            cafe.is_active = False
            db.session.commit()
            flash(f"Disabled {cafe.name}.", "success")
            return redirect(url_for("admin_cafes"))

        if action == "archive":
            cafe.is_active = False
            cafe.is_archived = True
            db.session.commit()
            flash(f"Archived {cafe.name}.", "success")
            return redirect(url_for("admin_cafes"))

        if action == "reopen":
            cafe.is_archived = False
            cafe.is_active = True
            db.session.commit()
            flash(f"Reopened {cafe.name}.", "success")
            return redirect(url_for("admin_cafes"))

        if action == "delete":
            if not cafe.is_archived:
                flash("Only archived cafes can be deleted.", "danger")
                return redirect(url_for("admin_cafes"))
            cafe_name = cafe.name
            db.session.delete(cafe)
            db.session.commit()
            flash(f"Deleted {cafe_name}.", "success")
            return redirect(url_for("admin_cafes"))

        if action == "set_owner":
            member_id = (request.form.get("owner_member_id") or "").strip()
            if not member_id.isdigit():
                flash("Pick a manager to make cafe owner.", "danger")
                return redirect(url_for("admin_cafes"))
            member = db.session.get(CafeMember, int(member_id))
            if not member or member.cafe_id != cafe.id or not member.is_active:
                flash("Manager not found.", "danger")
                return redirect(url_for("admin_cafes"))
            if member.role not in ("owner", "manager"):
                flash("Only managers can become cafe owner.", "danger")
                return redirect(url_for("admin_cafes"))
            assign_membership_role(member, "owner")
            db.session.commit()
            flash("Cafe owner updated.", "success")
            return redirect(url_for("admin_cafes"))

        flash("Unknown cafe action.", "danger")
        return redirect(url_for("admin_cafes"))

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
            phone_number = (request.form.get("phone_number") or "").strip()
            is_admin = request.form.get("is_global_admin") == "on"
            is_active = request.form.get("is_active") == "on"

            if not username or not email:
                flash("Username and email required.", "danger")
                return redirect(url_for("admin_user_create"))
            blocked = get_blocked_contact(email=email, phone_number=phone_number)
            if blocked:
                flash(blocked_contact_message(blocked), "danger")
                return redirect(url_for("admin_user_create"))
            if User.query.filter_by(username=username).first():
                flash("Username already taken.", "danger")
                return redirect(url_for("admin_user_create"))
            if User.query.filter_by(email=email).first():
                flash("Email already used.", "danger")
                return redirect(url_for("admin_user_create"))
            normalized_phone = normalize_phone(phone_number)
            if normalized_phone and UserContact.query.filter_by(phone_search=normalized_phone).first():
                flash("Phone number already used.", "danger")
                return redirect(url_for("admin_user_create"))

            u = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(secrets.token_urlsafe(32)),
                pending_email=None,
                email_verified_at=None,
                requires_password_setup=True,
                requires_email_verification=True,
                is_active=is_active,
                is_global_admin=is_admin,
            )
            db.session.add(u)
            db.session.flush()
            upsert_user_contact(u.id, phone_number)
            db.session.commit()

            email_sent, email_message, setup_url = send_new_user_setup_email(
                user=u,
                created_by_label=f"An admin from {ensure_global_settings().site_name}",
            )

            if email_sent:
                flash("User created and welcome email sent.", "success")
            else:
                flash(f"User created, but email could not be sent. Setup link: {setup_url} ({email_message})", "warning")
            return redirect(url_for("admin_users"))

        cafes = (
            Cafe.query
            .filter(Cafe.is_active == True, Cafe.is_archived == False)  # noqa: E712
            .order_by(Cafe.name.asc())
            .all()
        )
        return render_template("admin_user_create.html", cafes=cafes)

    @app.get("/admin/users/<int:user_id>")
    @require_login
    @require_global_admin
    def admin_user_manage(user_id: int):
        u = db.session.get(User, user_id)
        if not u:
            abort(404)

        cafes = (
            Cafe.query
            .filter(Cafe.is_active == True, Cafe.is_archived == False)  # noqa: E712
            .order_by(Cafe.name.asc())
            .all()
        )
        memberships = CafeMember.query.filter_by(user_id=u.id).order_by(CafeMember.created_at.desc()).all()
        cafe_map = {c.id: c for c in Cafe.query.order_by(Cafe.name.asc()).all()}

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

        if is_protected_super_admin(u) and action in {"delete_user", "toggle_active", "set_global_admin"}:
            flash("The protected super admin account cannot be deleted, suspended, or demoted.", "danger")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        if action == "delete_user":
            actor = current_user()
            if actor and actor.id == u.id:
                flash("You cannot delete your own account.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))
            owner_membership = CafeMember.query.filter_by(user_id=u.id, role="owner", is_active=True).first()
            if owner_membership:
                owner_cafe = db.session.get(Cafe, owner_membership.cafe_id)
                cafe_name = owner_cafe.name if owner_cafe else "that cafe"
                flash(f"Transfer cafe owner role for {cafe_name} before deleting this account.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))
            db.session.delete(u)
            db.session.commit()
            flash("User account deleted.", "success")
            return redirect(url_for("admin_users"))

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

        if action == "send_setup_email":
            u.requires_password_setup = True
            u.requires_email_verification = True
            db.session.commit()
            email_sent, email_message, setup_url = send_new_user_setup_email(
                user=u,
                created_by_label=f"An admin from {ensure_global_settings().site_name}",
            )
            if email_sent:
                flash("Setup email sent.", "success")
            else:
                flash(f"Setup email could not be sent. Setup link: {setup_url} ({email_message})", "warning")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        if action == "force_password_reset":
            u.password_hash = generate_password_hash(secrets.token_urlsafe(32))
            u.requires_password_setup = True
            u.requires_email_verification = True
            db.session.commit()
            email_sent, email_message, setup_url = send_new_user_setup_email(
                user=u,
                created_by_label=f"An admin from {ensure_global_settings().site_name}",
            )
            if email_sent:
                flash("Password reset email sent.", "success")
            else:
                flash(f"Password reset email could not be sent. Setup link: {setup_url} ({email_message})", "warning")
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

            if role not in ("staff", "manager", "owner"):
                role = "staff"
            if not cafe_id.isdigit():
                flash("Pick a cafe.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))

            cafe = db.session.get(Cafe, int(cafe_id))
            if not cafe or not cafe_is_available(cafe):
                flash("Cafe not found.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))

            mem = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not mem:
                mem = CafeMember(user_id=u.id, cafe_id=cafe.id, role=role, is_active=is_active)
                db.session.add(mem)
            else:
                assign_membership_role(mem, role)
                mem.is_active = is_active

            if role == "owner":
                assign_membership_role(mem, "owner")

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
            if mem.role == "owner":
                flash("Transfer the cafe owner role before removing this membership.", "danger")
                return redirect(url_for("admin_user_manage", user_id=user_id))
            db.session.delete(mem)
            db.session.commit()
            flash("Membership removed.", "success")
            return redirect(url_for("admin_user_manage", user_id=user_id))

        flash("Unknown action.", "danger")
        return redirect(url_for("admin_user_manage", user_id=user_id))




