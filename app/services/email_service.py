"""
email_service.py

This service handles system email sending for UniTrack.

Teaching idea:
Instead of placing email logic directly inside routes,
we move it into a service file.

Why this is better:
- routes stay clean
- email logic becomes reusable
- future features can use the same service
- easier to debug and maintain

Current goal:
- send real password reset emails with secure reset links

Important truth:
This version uses Python SMTP directly.
That means UniTrack can send real emails without needing
a heavy external extension first.

Now upgraded:
- secure reset token support
- reset URL generation
- expiration-aware password recovery email

Later we can still upgrade this service with:
- HTML email templates
- branded email design
- account activation emails
- notification emails
"""

import smtplib
from email.message import EmailMessage

from flask import current_app

from app.services.password_reset_service import generate_password_reset_token


def get_app_base_url():
    """
    Return the base URL used to build links sent by email.

    Teaching idea:
    Email links must point back to the UniTrack application.

    For local development, this defaults to localhost:5000.
    Later, in production, we can change APP_BASE_URL in config.py
    to the real deployed domain.
    """

    app_base_url = current_app.config.get("APP_BASE_URL", "http://127.0.0.1:5000")
    return str(app_base_url).rstrip("/")


def send_email(to_email, subject, body):
    """
    Send a real email using SMTP settings from config.py.

    Teaching idea:
    We read all mail settings from Flask config,
    so the service stays flexible and professional.
    """

    mail_server = current_app.config.get("MAIL_SERVER")
    mail_port = current_app.config.get("MAIL_PORT")
    mail_use_tls = current_app.config.get("MAIL_USE_TLS")
    mail_use_ssl = current_app.config.get("MAIL_USE_SSL")
    mail_username = current_app.config.get("MAIL_USERNAME")
    mail_password = current_app.config.get("MAIL_PASSWORD")
    mail_default_sender = current_app.config.get("MAIL_DEFAULT_SENDER")

    if not mail_server:
        raise ValueError("MAIL_SERVER is not configured")

    if not mail_port:
        raise ValueError("MAIL_PORT is not configured")

    if not mail_username:
        raise ValueError("MAIL_USERNAME is not configured")

    if not mail_password:
        raise ValueError("MAIL_PASSWORD is not configured")

    if not mail_default_sender:
        raise ValueError("MAIL_DEFAULT_SENDER is not configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail_default_sender
    message["To"] = to_email
    message.set_content(body)

    if mail_use_ssl:
        with smtplib.SMTP_SSL(mail_server, mail_port) as server:
            server.login(mail_username, mail_password)
            server.send_message(message)
        return True

    with smtplib.SMTP(mail_server, mail_port) as server:
        server.ehlo()

        if mail_use_tls:
            server.starttls()
            server.ehlo()

        server.login(mail_username, mail_password)
        server.send_message(message)

    return True


def send_password_reset_email(user):
    """
    Send the password reset email with a secure reset link.

    Teaching idea:
    This is now a real recovery flow step.

    Flow:
    1. Generate secure signed token
    2. Build reset URL
    3. Email the URL to the verified user

    Important security note:
    The token expires automatically based on config.py.
    """

    token = generate_password_reset_token(user)
    base_url = get_app_base_url()
    reset_url = f"{base_url}/auth/reset-password?token={token}"

    expires_minutes = current_app.config.get("PASSWORD_RESET_TOKEN_EXPIRES_MINUTES", 30)

    subject = "UniTrack Password Reset Link"

    body = f"""
Hello {user.first_name} {user.last_name},

We received a password reset request for your UniTrack account.

Account email:
{user.email}

To create a new password, open this secure reset link:

{reset_url}

Important:
- This link expires in {expires_minutes} minutes.
- If you did not request this reset, please ignore this email.
- For security, do not share this link with anyone.

UniTrack Security System
Universidad Politécnica
""".strip()

    return send_email(
        to_email=user.email,
        subject=subject,
        body=body
    )