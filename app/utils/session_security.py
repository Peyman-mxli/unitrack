"""Session binding: invalidate other sessions when any password hash changes."""
import hashlib
import hmac

from flask import current_app, session


def password_session_tag(user):
    secret = current_app.config["SECRET_KEY"]
    message = f"unitrack-session-v1:{user.id}:{user.password_hash}".encode("utf-8")
    return hmac.new(str(secret).encode("utf-8"), message, hashlib.sha256).hexdigest()


def bind_authenticated_session(user):
    """Call immediately after a successful login or password change."""
    session["password_session_tag"] = password_session_tag(user)


def is_current_password_session(user):
    supplied = session.get("password_session_tag")
    return bool(supplied) and hmac.compare_digest(str(supplied), password_session_tag(user))
