import os
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import render_template, request, url_for
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from models import (
    ActivityLog,
    BlockedContact,
    Cafe,
    CafeCustomerNote,
    CafeMember,
    CafeSettings,
    EmailSettings,
    EmailVerificationToken,
    GlobalSettings,
    LoyaltyCard,
    Notification,
    PasswordResetToken,
    RewardTier,
    StaffInvite,
    User,
    UserContact,
    db,
)


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


def is_protected_super_admin(user: User | None) -> bool:
    return bool(user and user.email == "admin@local" and user.is_global_admin)


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
    if not row or row.used_at is not None or row.expires_at < datetime.utcnow():
        return None
    return row


def send_email_verification_email(
    *,
    user: User,
    email: str,
    purpose_label: str,
    cafe: Cafe | None = None,
) -> tuple[bool, str, str]:
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


def upsert_customer_meta(
    cafe_id: int,
    user_id: int,
    *,
    note: str | None,
    is_flagged: bool,
    updated_by_user_id: int | None,
) -> CafeCustomerNote:
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
        extra.append(reason_note)
    suffix = f" ({' | '.join(extra)})" if extra else ""
    return f"{actor_name} {base_note}{suffix}"


def normalize_phone(phone_number: str) -> str:
    return re.sub(r"\D+", "", (phone_number or "").strip())


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def get_user_contact(user_id: int) -> UserContact | None:
    return UserContact.query.filter_by(user_id=user_id).first()


def upsert_user_contact(user_id: int, phone_number: str | None) -> UserContact:
    contact = get_user_contact(user_id)
    if not contact:
        contact = UserContact(user_id=user_id)
        db.session.add(contact)
    contact.phone_number = (phone_number or "").strip() or None
    contact.phone_search = normalize_phone(phone_number) or None
    return contact


def get_blocked_contact(*, email: str | None = None, phone_number: str | None = None) -> BlockedContact | None:
    normalized_email = normalize_email(email) if email else None
    normalized_phone = normalize_phone(phone_number) if phone_number else None

    if normalized_email:
        row = BlockedContact.query.filter_by(block_type="email", normalized_value=normalized_email).first()
        if row:
            return row
    if normalized_phone:
        row = BlockedContact.query.filter_by(block_type="phone", normalized_value=normalized_phone).first()
        if row:
            return row
    return None


def get_user_block(user: User | None) -> BlockedContact | None:
    if not user:
        return None
    contact = get_user_contact(user.id)
    return get_blocked_contact(email=user.email, phone_number=contact.phone_number if contact else None)


def blocked_contact_message(blocked: BlockedContact | None) -> str:
    if not blocked:
        return "This account is blocked."
    label = "email address" if blocked.block_type == "email" else "phone number"
    note = f" Reason: {blocked.note}" if blocked.note else ""
    return f"This {label} is blocked from using the platform.{note}"


def send_app_email(
    *,
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> tuple[bool, str]:
    settings = ensure_email_settings()
    if not settings.is_enabled:
        return False, "Email sending is disabled."
    if not settings.smtp_host or not settings.from_email:
        return False, "SMTP host or from email is not configured."

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{settings.from_name} <{settings.from_email}>" if settings.from_name else settings.from_email
    msg["To"] = to_email
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
            if settings.use_tls:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password or "")
            smtp.send_message(msg)
    except Exception as exc:
        return False, str(exc)
    return True, "sent"


def create_password_setup_token(user: User) -> PasswordResetToken:
    active_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).all()
    now = datetime.utcnow()
    for token_row in active_tokens:
        token_row.used_at = now

    token = PasswordResetToken(
        user_id=user.id,
        expires_at=now + timedelta(hours=max(ensure_global_settings().password_reset_expiry_hours, 1)),
    )
    db.session.add(token)
    db.session.commit()
    return token


def send_new_user_setup_email(
    *,
    user: User,
    created_by_label: str,
    cafe: Cafe | None = None,
) -> tuple[bool, str, str]:
    global_settings = ensure_global_settings()
    token = create_password_setup_token(user)
    setup_url = url_for("reset_password", token=token.token, _external=True)
    branding = get_email_branding(cafe)
    email_sent, email_message = send_app_email(
        to_email=user.email,
        subject=f"Set up your {branding['email_brand_name']} account",
        text_body=(
            f"Hello {user.username},\n\n"
            f"{created_by_label} created an account for you.\n\n"
            f"Set your password here:\n{setup_url}\n"
        ),
        html_body=render_template(
            "emails/new_user_welcome_email.html",
            site_name=global_settings.site_name,
            username=user.username,
            created_by_label=created_by_label,
            setup_url=setup_url,
            **branding,
        ),
    )
    return email_sent, email_message, setup_url


def send_staff_invite_email(*, invite: StaffInvite, cafe: Cafe, site_name: str) -> tuple[bool, str, str]:
    invite_url = url_for("invite_accept", token=invite.token, _external=True)
    branding = get_email_branding(cafe)
    email_sent, email_message = send_app_email(
        to_email=invite.email,
        subject=f"You've been invited to {cafe.name}",
        text_body=(
            f"You have been invited to join {cafe.name} as {invite.role}.\n\n"
            f"Accept the invite here:\n{invite_url}\n"
        ),
        html_body=render_template(
            "emails/invite_email.html",
            site_name=site_name,
            cafe_name=cafe.name,
            role=invite.role,
            invite_url=invite_url,
            **branding,
        ),
    )
    return email_sent, email_message, invite_url


def ensure_loyalty_card(user: User, cafe: Cafe) -> LoyaltyCard:
    card = LoyaltyCard.query.filter_by(user_id=user.id, cafe_id=cafe.id).first()
    if card:
        return card

    card = LoyaltyCard(user_id=user.id, cafe_id=cafe.id)
    db.session.add(card)
    db.session.commit()
    return card


def get_active_reward_tiers(cafe_id: int):
    return (
        RewardTier.query
        .filter_by(cafe_id=cafe_id, is_active=True)
        .order_by(RewardTier.points_required.asc(), RewardTier.created_at.asc())
        .all()
    )


def get_best_unlocked_tier(points_balance: int, cafe_id: int):
    tiers = get_active_reward_tiers(cafe_id)
    unlocked = [tier for tier in tiers if points_balance >= tier.points_required]
    return unlocked[-1] if unlocked else None


def get_next_tier(points_balance: int, cafe_id: int):
    tiers = get_active_reward_tiers(cafe_id)
    for tier in tiers:
        if points_balance < tier.points_required:
            return tier
    return None


def get_loyalty_progress(card: LoyaltyCard, settings: CafeSettings, cafe_id: int | None = None) -> dict:
    if settings.loyalty_type == "points":
        current = card.points_balance
        required = max(settings.points_required, 1)
        unlocked_tier = None
        next_tier = None
        reward_name = settings.reward_name
        unit_label = "points"
    elif settings.loyalty_type == "tiered_points" and cafe_id is not None:
        unlocked_tier = get_best_unlocked_tier(card.points_balance, cafe_id)
        next_tier = get_next_tier(card.points_balance, cafe_id)
        current = card.points_balance
        required = next_tier.points_required if next_tier else (unlocked_tier.points_required if unlocked_tier else 0)
        reward_name = unlocked_tier.reward_name if unlocked_tier else (next_tier.reward_name if next_tier else settings.reward_name)
        unit_label = "points"
    else:
        current = card.stamp_count
        required = max(settings.stamps_required, 1)
        unlocked_tier = None
        next_tier = None
        reward_name = settings.reward_name
        unit_label = "stamps"

    remaining = max(required - current, 0) if required else 0
    progress = min((current / required) * 100, 100) if required else 100
    return {
        "current": current,
        "required": required,
        "remaining": remaining,
        "progress": progress,
        "unit_label": unit_label,
        "reward_name": reward_name,
        "unlocked_tier": unlocked_tier,
        "next_tier": next_tier,
    }


def apply_loyalty_increment(card: LoyaltyCard, settings: CafeSettings, cafe_id: int) -> tuple[int, int]:
    stamp_delta = 0
    points_delta = 0

    if settings.loyalty_type == "stamps":
        if not card.reward_available:
            card.stamp_count += 1
            stamp_delta = 1
            if card.stamp_count >= max(settings.stamps_required, 1):
                card.reward_available = True
    else:
        if not card.reward_available:
            increment = max(settings.points_per_purchase, 1)
            card.points_balance += increment
            points_delta = increment

            if settings.loyalty_type == "points":
                if card.points_balance >= max(settings.points_required, 1):
                    card.reward_available = True
            else:
                unlocked_tier = get_best_unlocked_tier(card.points_balance, cafe_id)
                card.unlocked_tier_id = unlocked_tier.id if unlocked_tier else None
                card.reward_available = bool(unlocked_tier)

    card.updated_at = datetime.utcnow()
    return stamp_delta, points_delta


def reset_loyalty(card: LoyaltyCard, settings: CafeSettings) -> None:
    card.stamp_count = 0
    if settings.loyalty_type in ("points", "tiered_points"):
        card.points_balance = 0
    card.reward_available = False
    card.unlocked_tier_id = None
    card.updated_at = datetime.utcnow()
    card.last_activity_at = datetime.utcnow()


def log_activity(
    *,
    cafe_id: int,
    actor_user_id: int | None,
    target_user_id: int | None,
    action: str,
    note: str | None = None,
    stamp_delta: int = 0,
    points_delta: int = 0,
) -> None:
    db.session.add(ActivityLog(
        cafe_id=cafe_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        action=action,
        note=note,
        stamp_delta=stamp_delta,
        points_delta=points_delta,
    ))
    db.session.commit()


def create_notification(user_id: int, cafe_id: int | None, title: str, message: str) -> None:
    db.session.add(Notification(
        user_id=user_id,
        cafe_id=cafe_id,
        title=title,
        message=message,
    ))
    db.session.commit()


def get_valid_password_reset(token: str) -> PasswordResetToken | None:
    row = PasswordResetToken.query.filter_by(token=token).first()
    if not row or row.used_at is not None or row.expires_at < datetime.utcnow():
        return None
    return row


def ensure_sqlite_schema_updates() -> None:
    engine = db.session.get_bind()
    if engine.dialect.name != "sqlite":
        return

    db.session.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)"))
    completed = {
        row[0]
        for row in db.session.execute(text("SELECT name FROM schema_migrations")).fetchall()
    }

    def column_names(table_name: str) -> set[str]:
        return {
            row[1]
            for row in db.session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
        }

    migrations = [
        (
            "20260331_add_user_pending_email_fields",
            lambda: [
                db.session.execute(text("ALTER TABLE users ADD COLUMN pending_email VARCHAR(255)"))
                for _ in [0] if "pending_email" not in column_names("users")
            ],
        ),
        (
            "20260331_add_user_email_verified_at",
            lambda: [
                db.session.execute(text("ALTER TABLE users ADD COLUMN email_verified_at DATETIME"))
                for _ in [0] if "email_verified_at" not in column_names("users")
            ],
        ),
        (
            "20260331_add_user_requires_password_setup",
            lambda: [
                db.session.execute(text("ALTER TABLE users ADD COLUMN requires_password_setup BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "requires_password_setup" not in column_names("users")
            ],
        ),
        (
            "20260331_add_user_requires_email_verification",
            lambda: [
                db.session.execute(text("ALTER TABLE users ADD COLUMN requires_email_verification BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "requires_email_verification" not in column_names("users")
            ],
        ),
        (
            "20260331_add_cafes_is_archived",
            lambda: [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "is_archived" not in column_names("cafes")
            ],
        ),
        (
            "20260331_add_cafes_public_fields",
            lambda: [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN public_location VARCHAR(255)"))
                for _ in [0] if "public_location" not in column_names("cafes")
            ] + [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN public_opening_hours TEXT"))
                for _ in [0] if "public_opening_hours" not in column_names("cafes")
            ] + [
                db.session.execute(text("ALTER TABLE cafes ADD COLUMN public_join_instructions TEXT"))
                for _ in [0] if "public_join_instructions" not in column_names("cafes")
            ],
        ),
        (
            "20260331_add_customer_note_moderation_fields",
            lambda: [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN is_suspended BOOLEAN NOT NULL DEFAULT 0"))
                for _ in [0] if "is_suspended" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspension_reason VARCHAR(255)"))
                for _ in [0] if "suspension_reason" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspension_note TEXT"))
                for _ in [0] if "suspension_note" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspended_by_user_id INTEGER"))
                for _ in [0] if "suspended_by_user_id" not in column_names("cafe_customer_notes")
            ] + [
                db.session.execute(text("ALTER TABLE cafe_customer_notes ADD COLUMN suspended_at DATETIME"))
                for _ in [0] if "suspended_at" not in column_names("cafe_customer_notes")
            ],
        ),
        (
            "20260331_create_email_verification_tokens",
            lambda: db.session.execute(text(
                """
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id INTEGER NOT NULL PRIMARY KEY,
                    token VARCHAR(255) NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    expires_at DATETIME NOT NULL,
                    used_at DATETIME,
                    created_at DATETIME,
                    FOREIGN KEY(user_id) REFERENCES users (id)
                )
                """
            )),
        ),
    ]

    for migration_name, migration_fn in migrations:
        if migration_name in completed:
            continue
        migration_fn()
        db.session.execute(
            text("INSERT INTO schema_migrations (name) VALUES (:name)"),
            {"name": migration_name},
        )

    db.session.commit()


def seed_global_admin() -> None:
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
