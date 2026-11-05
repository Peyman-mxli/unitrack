"""
config.py

This file stores the main configuration settings for the UniTrack project.

Teaching idea:
Instead of writing all settings directly inside the Flask app file,
we keep them here so the project is cleaner and easier to maintain.

Later, this file can hold:
- secret keys
- database path
- upload folder path
- debug settings
- session settings
- email settings
- password reset settings
- other environment-based configuration
"""

import os
from datetime import timedelta


class Config:
    """
    Main configuration class for UniTrack.

    A class is useful here because Flask can load all settings
    from one organized place.
    """

    # Render's TLS termination is public even when UNITRACK_ENV was omitted.
    IS_HOSTED = bool(
        os.environ.get("RENDER_SERVICE_ID") or
        os.environ.get("RENDER_EXTERNAL_HOSTNAME") or
        os.environ.get("RENDER") == "true"
    )

    # Base project folder path.
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Secret key for sessions and security.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Uploads folder.
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

    # Limit upload size later if needed.
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

    # Allowed image extensions for photo uploads.
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

    # Database configuration.
    DATABASE_NAME = "unitrack.db"
    DATABASE_PATH = os.path.join(BASE_DIR, DATABASE_NAME)

    DATABASE_URL = os.environ.get("DATABASE_URL")

    if DATABASE_URL:
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ALLOW_LEGACY_QR = os.environ.get("UNITRACK_ALLOW_LEGACY_QR", "False").lower() == "true"
    ENFORCE_OPERATOR_SCANS = os.environ.get("UNITRACK_ENV", "").lower() == "production"

    ADMIN_MFA_REQUIRED = os.environ.get("UNITRACK_REQUIRE_ADMIN_MFA", "true" if os.environ.get("UNITRACK_ENV", "").lower() == "production" else "false").lower() == "true"

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (os.environ.get("UNITRACK_ENV", "").lower() == "production" or IS_HOSTED)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_REFRESH_EACH_REQUEST = False

    # Flask debug mode for development.
    DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

    # ==========================================
    # APPLICATION BASE URL
    # ==========================================
    APP_BASE_URL = (
        os.environ.get("APP_BASE_URL")
        or ("https://" + os.environ["RENDER_EXTERNAL_HOSTNAME"]
            if os.environ.get("RENDER_EXTERNAL_HOSTNAME") else "http://127.0.0.1:5000")
    )

    # ==========================================
    # EMAIL CONFIGURATION
    # ==========================================

    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "False").lower() == "true"

    # MUST be the same Gmail account that has:
    # - 2-Step Verification enabled
    # - the App Password generated
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")

    # MUST be the App Password generated from peyman.mxli@gmail.com
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")

    # Usually same as sender account
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", MAIL_USERNAME)

    # Optional destination for public contact/error reports. Defaults to the
    # already configured SMTP account. No mail credentials are stored in Git.
    CONTACT_NOTIFY_EMAIL = os.environ.get("CONTACT_NOTIFY_EMAIL") or MAIL_USERNAME

    # ==========================================
    # PASSWORD RESET CONFIGURATION
    # ==========================================

    PASSWORD_RESET_TOKEN_EXPIRES_MINUTES = int(
        os.environ.get("PASSWORD_RESET_TOKEN_EXPIRES_MINUTES", 30)
    )