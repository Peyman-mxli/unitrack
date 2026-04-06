"""
validation_code_service.py

Business logic for UniTrack validation codes.

This service is responsible for:
- creating validation codes
- generating unique codes
- finding codes by value
- validating if a code can be used
- validating if a code matches a selected role
- marking codes as used
"""

from datetime import datetime, timedelta
import secrets
import string

from app.database import db
from app.models.validation_code_model import ValidationCode


ALLOWED_VALIDATION_CODE_ROLES = {
    "estudiante",
    "docente",
    "personal",
    "administrativo",
}


def normalize_role(role):
    """
    Normalize incoming role text for safe comparisons.
    """
    if not role:
        return None

    return str(role).strip().lower()


def generate_random_code(length=8):
    """
    Generate a secure uppercase alphanumeric validation code.
    """
    characters = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def generate_unique_code(length=8):
    """
    Generate a code that does not already exist in the database.
    """
    while True:
        code = generate_random_code(length=length)
        existing_code = get_validation_code_by_code(code)

        if not existing_code:
            return code


def create_validation_code(generated_by_user_id, role, expires_in_hours=24):
    """
    Create and save a validation code for one specific role.

    Parameters:
    - generated_by_user_id: admin user id
    - role: role allowed by this code
    - expires_in_hours: validity duration

    Returns:
    - created ValidationCode object
    """
    if not generated_by_user_id:
        raise ValueError("generated_by_user_id is required")

    normalized_role = normalize_role(role)

    if not normalized_role:
        raise ValueError("role is required")

    if normalized_role not in ALLOWED_VALIDATION_CODE_ROLES:
        raise ValueError("invalid role for validation code")

    code = generate_unique_code(length=8)
    expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)

    validation_code = ValidationCode(
        code=code,
        role=normalized_role,
        generated_by=generated_by_user_id,
        expires_at=expires_at
    )

    try:
        db.session.add(validation_code)
        db.session.commit()
        return validation_code
    except Exception:
        db.session.rollback()
        raise


def get_validation_code_by_code(code):
    """
    Find one validation code by its text value.
    """
    if not code:
        return None

    clean_code = str(code).strip().upper()

    return db.session.execute(
        db.select(ValidationCode).filter_by(code=clean_code)
    ).scalar_one_or_none()


def validate_code_for_use(code, selected_role=None):
    """
    Check if a validation code exists and is still usable.

    If selected_role is provided, also verify that the code
    is assigned to that exact role.

    Returns:
    - (True, validation_code_object, None) if valid
    - (False, None, error_message) if invalid
    """
    validation_code = get_validation_code_by_code(code)

    if not validation_code:
        return False, None, "Validation code not found"

    if validation_code.is_used:
        return False, None, "Validation code has already been used"

    if validation_code.is_expired():
        return False, None, "Validation code has expired"

    if selected_role is not None:
        normalized_role = normalize_role(selected_role)

        if not normalized_role:
            return False, None, "Selected role is required"

        if not validation_code.matches_role(normalized_role):
            return False, None, "Validation code does not match the selected role"

    return True, validation_code, None


def mark_validation_code_as_used(validation_code, used_by_user_id):
    """
    Mark a validation code as consumed.

    Why this matters:
    - one code should not be reused many times
    - we keep audit history
    - admin can later track who used which code
    """
    if not validation_code:
        return None

    try:
        validation_code.is_used = True
        validation_code.used_at = datetime.utcnow()
        validation_code.used_by_user_id = used_by_user_id

        db.session.commit()
        return validation_code
    except Exception:
        db.session.rollback()
        raise