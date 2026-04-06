"""
security.py

This file handles password hashing and verification.
"""

from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(password: str) -> str:
    """
    Convert plain password into hashed version.
    """

    if not password:
        raise ValueError("Password is required")

    password = str(password).strip()

    if not password:
        raise ValueError("Password cannot be empty")

    return generate_password_hash(password)


def verify_password(hash_value: str, password: str) -> bool:
    """
    Check if entered password matches stored hash.
    """

    if not hash_value or not password:
        return False

    try:
        return check_password_hash(hash_value, str(password))
    except Exception:
        return False