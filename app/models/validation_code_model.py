"""
validation_code_model.py

This table stores admin-generated validation codes.

Purpose:
Validation codes are required for account registration.

Security idea:
- only admin can create codes
- each code is tied to one specific role
- a code can only be used one time
- a code can expire
- a user can only register with the role allowed by that code
"""

from datetime import datetime

from app.database import db


class ValidationCode(db.Model):
    """
    ValidationCode table.

    Each row represents one generated code.

    Teaching idea:
    Think of this like a one-time permission ticket.

    Admin creates the code.
    The code is assigned to one specific role.
    Another user uses the code.
    After that, the code becomes invalid.
    """

    __tablename__ = "validation_codes"

    id = db.Column(db.Integer, primary_key=True)

    # The actual validation string users must enter.
    code = db.Column(db.String(50), unique=True, nullable=False, index=True)

    # Role allowed by this validation code.
    # Examples:
    # - estudiante
    # - docente
    # - personal
    # - administrativo
    role = db.Column(db.String(50), nullable=False, index=True)

    # Which admin generated this code.
    generated_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    # Whether this code was already consumed.
    is_used = db.Column(db.Boolean, default=False, nullable=False)

    # When the code was used.
    used_at = db.Column(db.DateTime, nullable=True)

    # Which user consumed this code.
    used_by_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    # Optional expiration date.
    # If current time passes this value, the code is no longer valid.
    expires_at = db.Column(db.DateTime, nullable=True)

    # When this code was created.
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def is_expired(self):
        """
        Return True if the validation code is already expired.

        Important:
        If expires_at is empty, we consider the code as non-expiring.
        """
        if not self.expires_at:
            return False

        return datetime.utcnow() > self.expires_at

    def can_be_used(self):
        """
        Return True only if the code is still valid.

        Rules:
        - cannot be already used
        - cannot be expired
        """
        if self.is_used:
            return False

        if self.is_expired():
            return False

        return True

    def matches_role(self, selected_role):
        """
        Return True only if the provided role matches
        the role assigned to this validation code.
        """
        if not selected_role:
            return False

        return self.role == str(selected_role).strip().lower()

    def __repr__(self):
        return (
            f"<ValidationCode code={self.code} "
            f"role={self.role} used={self.is_used}>"
        )