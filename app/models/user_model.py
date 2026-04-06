"""
user_model.py

Professional User model for UniTrack.

This model supports:
- role based access
- admin system
- account activation
- login tracking
- user language preference
- permanent UniTrack public user ID

Important temporary update:
Relationship fields for class/attendance modules are disabled for now
so the admin system can start correctly without unresolved model imports.

They can be restored later when those models are ready and connected.
"""

from datetime import datetime
from flask_login import UserMixin

from app.database import db


class User(UserMixin, db.Model):
    """
    User table for UniTrack.

    This table stores the main identity and security data
    for each system account.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # Permanent public user ID
    # Example:
    # UT-UPBC-0001
    user_id_code = db.Column(
        db.String(20),
        unique=True,
        nullable=True,
        index=True
    )

    # Identity
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)

    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    phone = db.Column(db.String(20), nullable=False)

    # User preference
    # Current allowed values:
    # - en = English
    language = db.Column(
        db.String(10),
        nullable=False,
        default="en"
    )

    # Security
    password_hash = db.Column(db.String(255), nullable=False)

    # Role system
    role = db.Column(
        db.String(30),
        nullable=False,
        default="estudiante",
        index=True
    )

    # Account state
    must_change_password = db.Column(db.Boolean, default=False)
    is_active_user = db.Column(db.Boolean, default=True)

    # Optional profile photo
    photo_path = db.Column(db.String(255), nullable=True)

    # Login tracking
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Temporary:
    # class and attendance relationships are disabled for now
    # so startup and admin login can work cleanly

    @property
    def is_active(self):
        """
        Flask-Login compatibility.
        """
        return self.is_active_user

    def full_name(self):
        """
        Return full name in one clean string.
        """
        return f"{self.first_name} {self.last_name}".strip()

    def generate_user_id_code(self):
        """
        Generate the permanent UniTrack public user ID.

        Example:
        UT-UPBC-0001
        """
        if self.id is None:
            return None

        return f"UT-UPBC-{str(self.id).zfill(4)}"

    def ensure_user_id_code(self):
        """
        Keep a public user ID assigned if missing.
        """
        if not self.user_id_code and self.id is not None:
            self.user_id_code = self.generate_user_id_code()

        return self.user_id_code

    def __repr__(self):
        """
        Helpful for debugging in terminal.
        """
        return f"<User {self.username} ({self.role})>"