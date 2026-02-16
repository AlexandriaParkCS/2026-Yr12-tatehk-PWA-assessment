from datetime import datetime
import secrets
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Cafe(db.Model):
    __tablename__ = "cafes"

    id = db.Column(db.Integer, primary_key=True)

    # Human name + URL-friendly slug (used in links like /c/<slug>)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

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


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Global (platform) flags
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_global_admin = db.Column(db.Boolean, nullable=False, default=False)

    # QR token stays per user (works across all cafes)
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


class CafeMember(db.Model):
    """
    A user can have different roles at different cafes.
    role: 'manager' or 'staff'
    """
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

    # Settings you mentioned / sensible defaults:
    stamps_required = db.Column(db.Integer, nullable=False, default=9)
    reward_name = db.Column(db.String(80), nullable=False, default="Free Coffee")

    # Optional staff permissions (useful later):
    staff_can_redeem = db.Column(db.Boolean, nullable=False, default=True)

    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    cafe = db.relationship("Cafe", back_populates="settings")


class LoyaltyCard(db.Model):
    """
    A loyalty card is per user, per cafe.
    """
    __tablename__ = "loyalty_cards"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=False, index=True)

    stamp_count = db.Column(db.Integer, nullable=False, default=0)
    reward_available = db.Column(db.Boolean, nullable=False, default=False)

    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "cafe_id", name="uq_user_cafe_loyalty"),
    )

    user = db.relationship("User", back_populates="loyalty_cards")
    cafe = db.relationship("Cafe")  # simple relationship; add back_populates later if needed
