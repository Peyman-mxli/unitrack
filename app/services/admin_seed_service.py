"""
admin_seed_service.py

Seed service for creating the default UniTrack administrator.
"""

import os

from sqlalchemy import text

from app.database import db
from app.utils.security import hash_password


DEFAULT_ADMIN_DATA = {
    "first_name": "System",
    "last_name": "Administrator",
    "username": "Admin",
    "email": "admin@unitrack.local",
    "phone": "0000000000",
    "role": "administrativo",
    "language": "en",
    # Password is supplied through UNITRACK_INITIAL_ADMIN_PASSWORD, never Git.
    "password": None,
}


def seed_default_admin():
    """
    Create the default admin user if it does not already exist.
    Uses raw SQL to avoid ORM relationship-loading issues during startup.
    """

    existing_admin = db.session.execute(
        text("""
            SELECT id
            FROM users
            WHERE lower(username) = lower(:username)
            LIMIT 1
        """),
        {"username": DEFAULT_ADMIN_DATA["username"]}
    ).fetchone()

    if existing_admin:
        return existing_admin[0]

    # An existing database is always left intact. On a fresh install the
    # administrator is only created with an explicitly configured password.
    initial_password = os.environ.get("UNITRACK_INITIAL_ADMIN_PASSWORD", "")
    if not initial_password:
        return None
    if len(initial_password) < 12:
        raise ValueError("UNITRACK_INITIAL_ADMIN_PASSWORD must be at least 12 characters.")

    password_hash = hash_password(initial_password)

    db.session.execute(
        text("""
            INSERT INTO users (
                first_name,
                last_name,
                username,
                email,
                phone,
                password_hash,
                role,
                language,
                is_active_user,
                must_change_password
            )
            VALUES (
                :first_name,
                :last_name,
                :username,
                :email,
                :phone,
                :password_hash,
                :role,
                :language,
                :is_active_user,
                :must_change_password
            )
        """),
        {
            "first_name": DEFAULT_ADMIN_DATA["first_name"],
            "last_name": DEFAULT_ADMIN_DATA["last_name"],
            "username": DEFAULT_ADMIN_DATA["username"],
            "email": DEFAULT_ADMIN_DATA["email"],
            "phone": DEFAULT_ADMIN_DATA["phone"],
            "password_hash": password_hash,
            "role": DEFAULT_ADMIN_DATA["role"],
            "language": DEFAULT_ADMIN_DATA["language"],
            "is_active_user": True,
            "must_change_password": True,
        }
    )

    db.session.commit()

    created_admin = db.session.execute(
        text("""
            SELECT id
            FROM users
            WHERE username = :username
            LIMIT 1
        """),
        {"username": DEFAULT_ADMIN_DATA["username"]}
    ).fetchone()

    return created_admin[0] if created_admin else None