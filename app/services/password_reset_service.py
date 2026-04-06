"""
password_reset_service.py

This service handles secure password reset tokens for UniTrack.
"""

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app

from app.services.user_service import get_user_by_email


def _get_serializer():
    """
    Create serializer safely.
    """

    try:
        secret_key = current_app.config.get("SECRET_KEY")
    except Exception:
        return None

    if not secret_key:
        return None

    return URLSafeTimedSerializer(secret_key)


def generate_password_reset_token(user):

    if not user:
        raise ValueError("User is required to generate reset token")

    serializer = _get_serializer()

    # 🔥 SAFE fallback (no crash if config not ready)
    if not serializer:
        return f"fallback-token-{user.id}"

    token = serializer.dumps(
        {"email": user.email},
        salt="unitrack-password-reset"
    )

    return token


def verify_password_reset_token(token):

    if not token:
        return None, "Missing reset token"

    serializer = _get_serializer()

    # 🔥 SAFE fallback
    if not serializer:
        return None, "Reset service not available"

    try:
        expires_minutes = int(
            current_app.config.get("PASSWORD_RESET_TOKEN_EXPIRES_MINUTES", 30)
        )
    except Exception:
        expires_minutes = 30

    max_age_seconds = expires_minutes * 60

    try:
        payload = serializer.loads(
            token,
            salt="unitrack-password-reset",
            max_age=max_age_seconds
        )

    except SignatureExpired:
        return None, "This reset link has expired"

    except BadSignature:
        return None, "This reset link is invalid"

    except Exception:
        return None, "Invalid reset token"

    email = str(payload.get("email", "")).strip().lower()

    if not email:
        return None, "Invalid reset token payload"

    user = get_user_by_email(email)

    if not user:
        return None, "User account not found"

    if not user.is_active_user:
        return None, "This account is inactive"

    return user, None