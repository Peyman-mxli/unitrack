"""
user_service.py

User business logic layer.

Professional responsibilities:
- safe database operations
- duplicate safety
- user lookup helpers
- admin/user status helpers
- login activity update
"""

from datetime import datetime

from app.database import db
from app.models.user_model import User


def normalize_email(email):
    """
    Normalize email before saving or searching.
    """
    if not email:
        return None

    return str(email).strip().lower()


def normalize_username(username):
    """
    Normalize username before saving or searching.
    """
    if not username:
        return None

    return str(username).strip()


def create_user(
    first_name,
    last_name,
    username,
    email,
    phone,
    password_hash,
    role="estudiante",
    photo_path=None
):
    """
    Create and save new user safely.
    """

    normalized_username = normalize_username(username)
    normalized_email = normalize_email(email)

    if get_user_by_username(normalized_username):
        raise ValueError("Username already exists")

    if get_user_by_email(normalized_email):
        raise ValueError("Email already exists")

    user = User(
        first_name=first_name.strip() if first_name else None,
        last_name=last_name.strip() if last_name else None,
        username=normalized_username,
        email=normalized_email,
        phone=phone.strip() if phone else None,
        password_hash=password_hash,
        role=role,
        photo_path=photo_path.strip() if photo_path else None
    )

    try:
        db.session.add(user)
        db.session.commit()
        return user
    except Exception:
        db.session.rollback()
        raise


def get_user_by_username(username):
    """
    Find one user by username.
    """
    normalized_username = normalize_username(username)

    if not normalized_username:
        return None

    return db.session.execute(
        db.select(User).filter_by(username=normalized_username)
    ).scalar_one_or_none()


def get_user_by_email(email):
    """
    Find one user by email.
    """
    normalized_email = normalize_email(email)

    if not normalized_email:
        return None

    return db.session.execute(
        db.select(User).filter_by(email=normalized_email)
    ).scalar_one_or_none()


def get_user_by_id(user_id):
    """
    Find one user by primary key id.
    """
    if not user_id:
        return None

    return db.session.get(User, user_id)


def update_last_login(user):
    """
    Save the latest successful login time.
    """

    if not user:
        return None

    try:
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        return user
    except Exception:
        db.session.rollback()
        raise


def deactivate_user(user_id):
    """
    Deactivate one user account.
    """
    user = get_user_by_id(user_id)

    if not user:
        return None

    try:
        user.is_active_user = False
        db.session.commit()
        return user
    except Exception:
        db.session.rollback()
        raise


def activate_user(user_id):
    """
    Activate one user account.
    """
    user = get_user_by_id(user_id)

    if not user:
        return None

    try:
        user.is_active_user = True
        db.session.commit()
        return user
    except Exception:
        db.session.rollback()
        raise


def mark_user_must_change_password(user_id, must_change=True):
    """
    Mark whether the user must change password on first login.
    """
    user = get_user_by_id(user_id)

    if not user:
        return None

    try:
        user.must_change_password = must_change
        db.session.commit()
        return user
    except Exception:
        db.session.rollback()
        raise