import os
import io
import csv
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

import qrcode
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort,
    send_file, jsonify, send_from_directory, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_, func, text

from models import (
    db,
    User,
    GlobalSettings,
    EmailSettings,
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

    global_settings = ensure_global_settings()
    settings = build_default_cafe_settings(cafe.id, global_settings)
    db.session.add(settings)
    db.session.commit()
    return settings


def ensure_global_settings() -> GlobalSettings:
    settings = db.session.get(GlobalSettings, 1)
    if settings:
        return settings

    settings = GlobalSettings(id=1)
    db.session.add(settings)
    db.session.commit()
    return settings


def ensure_email_settings() -> EmailSettings:
    settings = db.session.get(EmailSettings, 1)
    if settings:
        return settings

    settings = EmailSettings(
        id=1,
        is_enabled=bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM_EMAIL")),
        smtp_host=os.environ.get("SMTP_HOST"),
        smtp_port=int(os.environ.get("SMTP_PORT", "587")),
        smtp_username=os.environ.get("SMTP_USERNAME"),
        smtp_password=os.environ.get("SMTP_PASSWORD"),
        from_email=os.environ.get("SMTP_FROM_EMAIL"),
        from_name=os.environ.get("SMTP_FROM_NAME", "Coffee Loyalty"),
        use_tls=os.environ.get("SMTP_USE_TLS", "true").strip().lower() not in ("0", "false", "no"),
    )
    db.session.add(settings)
    db.session.commit()
    return settings


def build_default_cafe_settings(cafe_id: int, global_settings: GlobalSettings) -> CafeSettings:
    return CafeSettings(
        cafe_id=cafe_id,
        stamps_required=max(global_settings.default_stamps_required, 1),
        points_required=max(global_settings.default_points_required, 1),
        points_per_purchase=max(global_settings.default_points_per_purchase, 1),
        reward_name=global_settings.default_reward_name,
        welcome_message=global_settings.default_welcome_message,
        invite_expiry_days=max(global_settings.default_invite_expiry_days, 1),
        allow_manager_invites=global_settings.default_allow_manager_invites,
    )


def cafe_is_available(cafe: Cafe | None) -> bool:
    return bool(cafe and cafe.is_active and not getattr(cafe, "is_archived", False))


def is_manager_role(role: str | None) -> bool:
    return role in ("owner", "manager")


def get_cafe_owner_membership(cafe_id: int) -> CafeMember | None:
    return CafeMember.query.filter_by(cafe_id=cafe_id, role="owner", is_active=True).first()


def assign_membership_role(member: CafeMember, role: str) -> None:
    role = (role or "staff").strip().lower()
    if role not in ("staff", "manager", "owner"):
        role = "staff"

    if role == "owner":
        current_owner = get_cafe_owner_membership(member.cafe_id)
        if current_owner and current_owner.id != member.id:
            current_owner.role = "manager"

    member.role = role
    member.is_active = True


def get_email_branding(cafe: Cafe | None = None) -> dict:
    global_settings = ensure_global_settings()
    accent_color = getattr(cafe, "accent_color", None) or "#2f5d50"
    secondary_color = getattr(cafe, "secondary_color", None) or "#f4efe7"
    logo_url = getattr(cafe, "logo_url", None)
    brand_name = cafe.name if cafe else global_settings.site_name
    return {
        "email_brand_name": brand_name,
        "email_logo_url": logo_url,
        "email_accent_color": accent_color,
        "email_secondary_color": secondary_color,
        "email_background_color": "#f7f3ee",
        "email_card_color": "#fffdf9",
        "email_text_color": "#2d2218",
        "email_muted_color": "#6b5a4c",
    }


def create_email_verification_token(user: User, email: str) -> EmailVerificationToken:
    active_tokens = EmailVerificationToken.query.filter_by(user_id=user.id, used_at=None).all()
    now = datetime.utcnow()
    for token_row in active_tokens:
        token_row.used_at = now

    token = EmailVerificationToken(
        user_id=user.id,
        email=email,
        expires_at=now + timedelta(hours=24),
    )
    db.session.add(token)
    db.session.commit()
    return token


def get_valid_email_verification(token: str) -> EmailVerificationToken | None:
    row = EmailVerificationToken.query.filter_by(token=token).first()
    if not row:
        return None
    if row.used_at is not None:
        return None
    if row.expires_at < datetime.utcnow():
        return None
    return row


def send_email_verification_email(*, user: User, email: str, purpose_label: str, cafe: Cafe | None = None) -> tuple[bool, str, str]:
    global_settings = ensure_global_settings()
    token = create_email_verification_token(user, email)
    verify_url = url_for("verify_email", token=token.token, _external=True)
    branding = get_email_branding(cafe)
    email_sent, email_message = send_app_email(
        to_email=email,
        subject=f"Verify your email for {branding['email_brand_name']}",
        text_body=(
            f"Hello {user.username},\n\n"
            f"{purpose_label}\n\n"
            f"Verify your email here:\n{verify_url}\n\n"
            "This link expires in 24 hours.\n"
        ),
        html_body=render_template(
            "emails/email_verification_email.html",
            site_name=global_settings.site_name,
            username=user.username,
            purpose_label=purpose_label,
            verify_url=verify_url,
            expiry_hours=24,
            **branding,
        ),
    )
    return email_sent, email_message, verify_url


def get_customer_meta(cafe_id: int, user_id: int) -> CafeCustomerNote | None:
    return CafeCustomerNote.query.filter_by(cafe_id=cafe_id, user_id=user_id).first()


def upsert_customer_meta(cafe_id: int, user_id: int, *, note: str | None, is_flagged: bool, updated_by_user_id: int | None) -> CafeCustomerNote:
    meta = get_customer_meta(cafe_id, user_id)
    if not meta:
        meta = CafeCustomerNote(cafe_id=cafe_id, user_id=user_id)
        db.session.add(meta)
    meta.note = (note or "").strip() or None
    meta.is_flagged = bool(is_flagged)
    meta.updated_by_user_id = updated_by_user_id
    meta.updated_at = datetime.utcnow()
    return meta


def customer_is_suspended(cafe_id: int, user_id: int) -> bool:
    meta = get_customer_meta(cafe_id, user_id)
    return bool(meta and getattr(meta, "is_suspended", False))


def update_customer_suspension(
    cafe_id: int,
    user_id: int,
    *,
    actor_user_id: int,
    is_suspended: bool,
    reason: str | None,
    note: str | None,
) -> CafeCustomerNote:
    meta = get_customer_meta(cafe_id, user_id)
    if not meta:
        meta = CafeCustomerNote(cafe_id=cafe_id, user_id=user_id)
        db.session.add(meta)
    meta.is_suspended = is_suspended
    meta.suspension_reason = (reason or "").strip() or None
    meta.suspension_note = (note or "").strip() or None
    meta.suspended_by_user_id = actor_user_id if is_suspended else None
    meta.suspended_at = datetime.utcnow() if is_suspended else None
    meta.updated_by_user_id = actor_user_id
    meta.updated_at = datetime.utcnow()
    return meta


def is_ajax_request() -> bool:
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"


def build_action_note(actor_name: str, base_note: str, reason_code: str, reason_note: str) -> str:
    extra = []
    if reason_code:
        extra.append(f"Reason: {reason_code.replace('_', ' ')}")
    if reason_note:
        extra.append(f"Note: {reason_note}")
    if extra:
        return f"{actor_name} {base_note} ({'; '.join(extra)})"
    return f"{actor_name} {base_note}"


def normalize_phone(phone_number: str) -> str:
    return re.sub(r"\D+", "", phone_number or "")


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def get_user_contact(user_id: int) -> UserContact | None:
    return UserContact.query.filter_by(user_id=user_id).first()


def upsert_user_contact(user_id: int, phone_number: str | None) -> UserContact:
    contact = get_user_contact(user_id)
    if not contact:
        contact = UserContact(user_id=user_id)
        db.session.add(contact)
    normalized = normalize_phone(phone_number or "")
    contact.phone_number = (phone_number or "").strip() or None
    contact.phone_search = normalized or None
    return contact


def get_blocked_contact(*, email: str | None = None, phone_number: str | None = None) -> BlockedContact | None:
    normalized_email = normalize_email(email or "")
    if normalized_email:
        blocked_email = BlockedContact.query.filter_by(block_type="email", normalized_value=normalized_email).first()
        if blocked_email:
            return blocked_email

    normalized_phone = normalize_phone(phone_number or "")
    if normalized_phone:
        blocked_phone = BlockedContact.query.filter_by(block_type="phone", normalized_value=normalized_phone).first()
        if blocked_phone:
            return blocked_phone

    return None


def get_user_block(user: User | None) -> BlockedContact | None:
    if not user:
        return None
    contact = get_user_contact(user.id)
    return get_blocked_contact(email=user.email, phone_number=contact.phone_number if contact else None)


def blocked_contact_message(blocked: BlockedContact | None) -> str:
    if not blocked:
        return "This contact has been blocked."
    contact_label = "email" if blocked.block_type == "email" else "phone number"
    if blocked.note:
        return f"This {contact_label} has been blocked. {blocked.note}"
    return f"This {contact_label} has been blocked."


def send_app_email(*, to_email: str, subject: str, text_body: str, html_body: str | None = None) -> tuple[bool, str]:
    settings = ensure_email_settings()
    if not settings.is_enabled:
        return (False, "Email sending is disabled.")
    if not settings.smtp_host or not settings.from_email:
        return (False, "Email settings are incomplete.")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{settings.from_name} <{settings.from_email}>" if settings.from_name else settings.from_email
    message["To"] = to_email
    message.set_content(text_body)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as server:
            if settings.use_tls:
                server.starttls()
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password or "")
            server.send_message(message)
        return (True, "Email sent.")
    except Exception as exc:
        return (False, str(exc))


def create_password_setup_token(user: User) -> PasswordResetToken:
    active_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).all()
    now = datetime.utcnow()
    for token_row in active_tokens:
        token_row.used_at = now

    global_settings = ensure_global_settings()
    token = PasswordResetToken(
        user_id=user.id,
        expires_at=now + timedelta(hours=max(global_settings.password_reset_expiry_hours, 1)),
    )
    db.session.add(token)
    db.session.commit()
    return token


def send_new_user_setup_email(*, user: User, created_by_label: str, cafe: Cafe | None = None) -> tuple[bool, str, str]:
    global_settings = ensure_global_settings()
    token = create_password_setup_token(user)
    setup_url = url_for("reset_password", token=token.token, _external=True)
    expiry_hours = max(global_settings.password_reset_expiry_hours, 1)
    cafe_name = cafe.name if cafe else None
    branding = get_email_branding(cafe)

    email_sent, email_message = send_app_email(
        to_email=user.email,
        subject=f"Welcome to {branding['email_brand_name']}",
        text_body=(
            f"Hello {user.username},\n\n"
            f"{created_by_label} created an account for you"
            f"{f' for {cafe_name}' if cafe_name else ''}.\n\n"
            f"Set your password here:\n{setup_url}\n\n"
            f"This link expires in {expiry_hours} hour(s).\n"
        ),
        html_body=render_template(
            "emails/new_user_welcome_email.html",
            site_name=global_settings.site_name,
            username=user.username,
            created_by_label=created_by_label,
            cafe_name=cafe_name,
            setup_url=setup_url,
            expiry_hours=expiry_hours,
            **branding,
        ),
    )
    return email_sent, email_message, setup_url


def send_staff_invite_email(*, invite: StaffInvite, cafe: Cafe, site_name: str) -> tuple[bool, str, str]:
    invite_url = url_for("invite_accept", token=invite.token, _external=True)
    branding = get_email_branding(cafe)
    email_sent, email_message = send_app_email(
        to_email=invite.email,
        subject=f"Invitation to join {branding['email_brand_name']}",
        text_body=(
            f"You have been invited to join {cafe.name} as {invite.role}.\n\n"
            f"Accept your invite here:\n{invite_url}\n\n"
            f"This invite expires on {invite.expires_at} UTC.\n"
        ),
        html_body=render_template(
            "emails/invite_email.html",
            site_name=site_name,
            cafe_name=cafe.name,
            role=invite.role,
            invite_email=invite.email,
            invite_url=invite_url,
            expires_at=invite.expires_at,
            **branding,
        ),
    )
    return email_sent, email_message, invite_url


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


def get_active_reward_tiers(cafe_id: int):
    return (
        RewardTier.query
        .filter_by(cafe_id=cafe_id, is_active=True)
        .order_by(RewardTier.points_required.asc())
        .all()
    )


def get_best_unlocked_tier(points_balance: int, cafe_id: int):
    tiers = get_active_reward_tiers(cafe_id)
    unlocked = None
    for tier in tiers:
        if points_balance >= tier.points_required:
            unlocked = tier
        else:
            break
    return unlocked


def get_next_tier(points_balance: int, cafe_id: int):
    tiers = get_active_reward_tiers(cafe_id)
    for tier in tiers:
        if points_balance < tier.points_required:
            return tier
    return None


def get_loyalty_progress(card: LoyaltyCard, settings: CafeSettings, cafe_id: int | None = None) -> dict:
    """
    Returns a normalised structure for templates and JSON.
    """
    if settings.loyalty_type == "tiered_points":
        current = card.points_balance
        unlocked_tier = get_best_unlocked_tier(current, cafe_id or card.cafe_id)
        next_tier = get_next_tier(current, cafe_id or card.cafe_id)

        if next_tier:
            required = next_tier.points_required
            progress = min(100, (current * 100) / required) if required > 0 else 0
            remaining = max(required - current, 0)
        else:
            required = unlocked_tier.points_required if unlocked_tier else max(current, 1)
            progress = 100
            remaining = 0

        return {
            "mode": "tiered_points",
            "current": current,
            "required": required,
            "progress": progress,
            "remaining": remaining,
            "unit_label": "points",
            "reward_name": unlocked_tier.reward_name if unlocked_tier else (next_tier.reward_name if next_tier else settings.reward_name),
            "unlocked_tier": unlocked_tier,
            "next_tier": next_tier,
        }

    if settings.loyalty_type == "points":
        required = max(settings.points_required, 1)
        current = card.points_balance
        progress = min(100, (current * 100) / required)
        remaining = max(required - current, 0)
        return {
            "mode": "points",
            "current": current,
            "required": required,
            "progress": progress,
            "remaining": remaining,
            "unit_label": "points",
            "reward_name": settings.reward_name,
            "unlocked_tier": None,
            "next_tier": None,
        }

    required = max(settings.stamps_required, 1)
    current = card.stamp_count
    progress = min(100, (current * 100) / required)
    remaining = max(required - current, 0)
    return {
        "mode": "stamps",
        "current": current,
        "required": required,
        "progress": progress,
        "remaining": remaining,
        "unit_label": "stamps",
        "reward_name": settings.reward_name,
        "unlocked_tier": None,
        "next_tier": None,
    }


def apply_loyalty_increment(card: LoyaltyCard, settings: CafeSettings, cafe_id: int) -> tuple[int, int]:
    """
    Returns (stamp_delta, points_delta)
    """
    if card.reward_available:
        return (0, 0)

    if settings.loyalty_type == "tiered_points":
        delta = max(settings.points_per_purchase, 1)
        card.points_balance += delta

        unlocked_tier = get_best_unlocked_tier(card.points_balance, cafe_id)
        if unlocked_tier:
            card.reward_available = True
            card.unlocked_tier_id = unlocked_tier.id

        return (0, delta)

    if settings.loyalty_type == "points":
        delta = max(settings.points_per_purchase, 1)
        card.points_balance += delta
        if card.points_balance >= settings.points_required:
            card.points_balance = settings.points_required
            card.reward_available = True
        return (0, delta)

    card.stamp_count += 1
    if card.stamp_count >= settings.stamps_required:
        card.stamp_count = settings.stamps_required
        card.reward_available = True
    return (1, 0)


def reset_loyalty(card: LoyaltyCard, settings: CafeSettings) -> None:
    if settings.loyalty_type in ("points", "tiered_points"):
        card.points_balance = 0
        card.unlocked_tier_id = None
    else:
        card.stamp_count = 0

    card.reward_available = False
    card.last_redeem_at = datetime.utcnow()
    card.last_activity_at = datetime.utcnow()


def log_activity(
    *,
    cafe_id: int,
    action: str,
    target_user_id: int,
    actor_user_id: int | None = None,
    stamp_delta: int = 0,
    points_delta: int = 0,
    note: str | None = None,
) -> None:
    row = ActivityLog(
        cafe_id=cafe_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        action=action,
        stamp_delta=stamp_delta,
        points_delta=points_delta,
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


def get_valid_password_reset(token: str) -> PasswordResetToken | None:
    reset = PasswordResetToken.query.filter_by(token=token).first()
    if not reset:
        return None
    if reset.used_at is not None:
        return None
    if reset.expires_at < datetime.utcnow():
        return None
    return reset


def ensure_sqlite_schema_updates() -> None:
    if db.engine.dialect.name != "sqlite":
        return

    db.session.execute(text("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """))

    def column_names(table_name: str) -> set[str]:
        return {
            row[1]
            for row in db.session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
        }

    migrations = [
        (
            "001_user_verification_columns",
            lambda: [
                db.session.execute(text("ALTER TABLE users ADD COLUMN pending_email VARCHAR(255)"))
                for _ in [0] if "pending_email" not in column_names("users")
            ] + [
                db.session.execute(text("ALTER TABLE users ADD COLUMN email_verified_at DATETIME"))
                for _ in [0] if "email_verified_at" not in column_names("users")
            ] + [
                db.session.execute(text("ALTER TABLE users ADD COLUMN requires_password_setup BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "requires_password_setup" not in column_names("users")
            ] + [
                db.session.execute(text("ALTER TABLE users ADD COLUMN requires_email_verification BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "requires_email_verification" not in column_names("users")
            ],
        ),
        (
            "002_cafe_archive_column",
            lambda: [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "is_archived" not in column_names("cafes")
            ],
        ),
        (
            "003_cafe_public_fields",
            lambda: [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN public_location VARCHAR(255)"))
                for _ in [0] if "public_location" not in column_names("cafes")
            ] + [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN public_opening_hours VARCHAR(255)"))
                for _ in [0] if "public_opening_hours" not in column_names("cafes")
            ] + [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN public_join_instructions VARCHAR(500)"))
                for _ in [0] if "public_join_instructions" not in column_names("cafes")
            ],
        ),
        (
            "004_customer_moderation_fields",
            lambda: [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN is_suspended BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "is_suspended" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspension_reason VARCHAR(120)"))
                for _ in [0] if "suspension_reason" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspension_note VARCHAR(255)"))
                for _ in [0] if "suspension_note" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspended_by_user_id INTEGER"))
                for _ in [0] if "suspended_by_user_id" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspended_at DATETIME"))
                for _ in [0] if "suspended_at" not in column_names("cafe_customer_notes")
            ],
        ),
    ]

    applied = {
        row[0]
        for row in db.session.execute(text("SELECT name FROM schema_migrations")).fetchall()
    }

    for migration_name, migration_fn in migrations:
        if migration_name in applied:
            continue
        migration_fn()
        db.session.execute(
            text("INSERT INTO schema_migrations (name) VALUES (:name)"),
            {"name": migration_name},
        )

    db.session.commit()


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
            flash("You don’t have access to that cafe yet. Ask staff to scan your QR first.", "danger")
            return redirect(url_for("select_cafe"))

        return redirect(url_for("cafe_home", cafe_slug=cafe.slug))

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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You donâ€™t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        return redirect(url_for("cafe_home", cafe_slug=cafe.slug))

        u = current_user()
        if not is_global_admin(u):
            member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            has_card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not member and not has_card:
                flash("You don’t have access to that cafe yet.", "danger")
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
            flash("You don’t have access to that cafe yet.", "danger")
            return redirect(url_for("select_cafe"))

        return redirect(url_for("cafe_card", cafe_slug=cafe.slug))

        u = current_user()
        if not is_global_admin(u):
            member = CafeMember.query.filter_by(user_id=u.id, cafe_id=cafe.id, is_active=True).first()
            has_card = LoyaltyCard.query.filter_by(user_id=u.id, cafe_id=cafe.id).first()
            if not member and not has_card:
                flash("You don’t have access to that cafe yet.", "danger")
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
        pending_email=None,
        email_verified_at=datetime.utcnow(),
        requires_password_setup=False,
        requires_email_verification=False,
        is_active=True,
        is_global_admin=True,
    )
    db.session.add(admin)
    db.session.commit()


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)
