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

    # Passwords are byte-exact secrets. Trimming silently changes the password
    # and can make some passwords impossible to use after an upgrade.
    if not isinstance(password, str):
        raise ValueError("Password must be text")

    return generate_password_hash(password, method="scrypt:32768:8:1")


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