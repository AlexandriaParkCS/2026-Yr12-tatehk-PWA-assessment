from datetime import datetime, timedelta
import secrets
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Cafe(db.Model):
    __tablename__ = "cafes"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Branding / theme
    logo_url = db.Column(db.String(500), nullable=True)
    accent_color = db.Column(db.String(20), nullable=False, default="#6f4e37")
    secondary_color = db.Column(db.String(20), nullable=False, default="#f5ede3")
    theme_mode = db.Column(db.String(20), nullable=False, default="light")   # light | dark | coffee | modern
    card_style = db.Column(db.String(20), nullable=False, default="rounded") # rounded | minimal | bold

    settings = db.relationship(
        "CafeSettings",
        back_populates="cafe",
        uselist=False,
        cascade="all, delete-orphan",
    )

    members = db.relationship(
        "CafeMember",
        back_populates="cafe",
        cascade="all, delete-orphan",
    )

    loyalty_cards = db.relationship(
        "LoyaltyCard",
        back_populates="cafe",
        cascade="all, delete-orphan",
    )

    activity_logs = db.relationship(
        "ActivityLog",
        back_populates="cafe",
        cascade="all, delete-orphan",
    )

    invites = db.relationship(
        "StaffInvite",
        back_populates="cafe",
        cascade="all, delete-orphan",
    )


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_global_admin = db.Column(db.Boolean, nullable=False, default=False)

    qr_token = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(32),
    )

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    memberships = db.relationship(
        "CafeMember",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    loyalty_cards = db.relationship(
        "LoyaltyCard",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    notifications = db.relationship(
        "Notification",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    activity_as_actor = db.relationship(
        "ActivityLog",
        foreign_keys="ActivityLog.actor_user_id",
        back_populates="actor_user",
        cascade="all, delete-orphan",
    )

    activity_as_target = db.relationship(
        "ActivityLog",
        foreign_keys="ActivityLog.target_user_id",
        back_populates="target_user",
        cascade="all, delete-orphan",
    )


class CafeMember(db.Model):
    __tablename__ = "cafe_members"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=False, index=True)

    role = db.Column(db.String(20), nullable=False)  # manager | staff
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "cafe_id", name="uq_user_cafe_membership"),
    )

    user = db.relationship("User", back_populates="memberships")
    cafe = db.relationship("Cafe", back_populates="members")


class CafeSettings(db.Model):
    __tablename__ = "cafe_settings"

    id = db.Column(db.Integer, primary_key=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), unique=True, nullable=False, index=True)

    # Loyalty mode
    loyalty_type = db.Column(db.String(20), nullable=False, default="stamps")  # stamps | points

    # Stamp mode
    stamps_required = db.Column(db.Integer, nullable=False, default=9)

    # Points mode
    points_required = db.Column(db.Integer, nullable=False, default=100)
    points_per_purchase = db.Column(db.Integer, nullable=False, default=10)

    reward_name = db.Column(db.String(80), nullable=False, default="Free Coffee")

    # Display settings
    show_qr_label = db.Column(db.Boolean, nullable=False, default=True)
    show_stamp_numbers = db.Column(db.Boolean, nullable=False, default=True)
    show_progress_bar = db.Column(db.Boolean, nullable=False, default=True)
    show_reward_badge = db.Column(db.Boolean, nullable=False, default=True)
    welcome_message = db.Column(db.String(255), nullable=False, default="Welcome back!")

    # Staff permissions
    staff_can_scan = db.Column(db.Boolean, nullable=False, default=True)
    staff_can_add_stamp = db.Column(db.Boolean, nullable=False, default=True)
    staff_can_redeem = db.Column(db.Boolean, nullable=False, default=True)
    staff_can_reset_loyalty = db.Column(db.Boolean, nullable=False, default=False)
    staff_can_change_password = db.Column(db.Boolean, nullable=False, default=False)

    # Customer behaviour
    allow_multi_cafe_cards = db.Column(db.Boolean, nullable=False, default=True)
    auto_create_card_on_first_scan = db.Column(db.Boolean, nullable=False, default=True)
    show_customer_history = db.Column(db.Boolean, nullable=False, default=True)
    enable_notifications = db.Column(db.Boolean, nullable=False, default=True)

    # Invite settings
    invite_expiry_days = db.Column(db.Integer, nullable=False, default=7)
    allow_manager_invites = db.Column(db.Boolean, nullable=False, default=True)
    default_invite_role = db.Column(db.String(20), nullable=False, default="staff")  # staff | manager

    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    cafe = db.relationship("Cafe", back_populates="settings")


class LoyaltyCard(db.Model):
    __tablename__ = "loyalty_cards"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=False, index=True)

    # Shared loyalty state
    reward_available = db.Column(db.Boolean, nullable=False, default=False)

    # Stamp mode
    stamp_count = db.Column(db.Integer, nullable=False, default=0)

    # Points mode
    points_balance = db.Column(db.Integer, nullable=False, default=0)

    # History helpers
    last_scan_at = db.Column(db.DateTime, nullable=True)
    last_redeem_at = db.Column(db.DateTime, nullable=True)
    last_activity_at = db.Column(db.DateTime, nullable=True)

    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "cafe_id", name="uq_user_cafe_loyalty"),
    )

    user = db.relationship("User", back_populates="loyalty_cards")
    cafe = db.relationship("Cafe", back_populates="loyalty_cards")


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)

    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    action = db.Column(db.String(40), nullable=False, index=True)
    # examples:
    # stamp_added, points_added, reward_redeemed, loyalty_reset,
    # membership_added, membership_removed, password_changed, invite_created

    stamp_delta = db.Column(db.Integer, nullable=False, default=0)
    points_delta = db.Column(db.Integer, nullable=False, default=0)
    note = db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    cafe = db.relationship("Cafe", back_populates="activity_logs")
    actor_user = db.relationship("User", foreign_keys=[actor_user_id], back_populates="activity_as_actor")
    target_user = db.relationship("User", foreign_keys=[target_user_id], back_populates="activity_as_target")


class StaffInvite(db.Model):
    __tablename__ = "staff_invites"

    id = db.Column(db.Integer, primary_key=True)

    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=False, index=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    email = db.Column(db.String(255), nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False, default="staff")  # staff | manager

    token = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(32),
    )

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    accepted_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.utcnow() + timedelta(days=7),
    )

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    cafe = db.relationship("Cafe", back_populates="invites")


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True, index=True)

    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.String(255), nullable=False)

    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    user = db.relationship("User", back_populates="notifications")