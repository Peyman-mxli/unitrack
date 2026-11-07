"""Unified password history and account lockout handling.

Password history starts when this feature is deployed; passwords used before
that time cannot be reconstructed. History is private to each account.
"""
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets

from app.database import db
from app.models.password_history_model import PasswordHistory
from app.models.login_security_model import LoginSecurityState
from app.utils.password_policy import new_password_error
from app.utils.security import hash_password, verify_password

MAX_FAILED_LOGINS = 5
LOGIN_LOCK_MINUTES = 5
EMAIL_UNLOCK_MINUTES = 15
REUSED_PASSWORD_MESSAGE = "No puedes volver a utilizar una contraseña anterior de esta cuenta."


def password_reuse_error(user, candidate):
    """Reject the current password and every previously saved password hash."""
    if not user or not isinstance(candidate, str):
        return None
    if verify_password(user.password_hash, candidate):
        return REUSED_PASSWORD_MESSAGE
    stored_hashes = db.session.execute(
        db.select(PasswordHistory.password_hash)
        .where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.id.desc())
    ).scalars()
    for old_hash in stored_hashes:
        if verify_password(old_hash, candidate):
            return REUSED_PASSWORD_MESSAGE
    return None


def set_new_password(user, candidate, *, force_change=False):
    """Change the password within the caller's transaction; caller must commit.

    All changes must use this function, including admin resets, forced changes
    and role profile settings. Add old hash and change the current hash atomically.
    """
    error = new_password_error(candidate, user) or password_reuse_error(user, candidate)
    if error:
        raise ValueError(error)
    db.session.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
    user.password_hash = hash_password(candidate)
    user.must_change_password = bool(force_change)


def is_login_locked(user, now=None):
    if not user:
        return False
    now = now or datetime.utcnow()
    state = db.session.get(LoginSecurityState, user.id)
    return bool(state and state.locked_until and state.locked_until > now)


def record_failed_login(user, now=None):
    """Return a random email approval token only on the fifth bad attempt.

    A lock is per account, independent of attacker IP or username/email alias.
    The existing per-IP request limit remains a separate defense.
    """
    now = now or datetime.utcnow()
    state = db.session.get(LoginSecurityState, user.id)
    if state is None:
        state = LoginSecurityState(user_id=user.id)
        db.session.add(state)
    if state.locked_until and state.locked_until > now:
        return None
    if state.locked_until and state.locked_until <= now:
        state.failed_attempts = 0
        state.locked_until = None
        state.unlock_token_hash = None
        state.unlock_expires_at = None
    state.failed_attempts += 1
    token = None
    if state.failed_attempts >= MAX_FAILED_LOGINS:
        state.failed_attempts = MAX_FAILED_LOGINS
        state.locked_until = now + timedelta(minutes=LOGIN_LOCK_MINUTES)
        token = secrets.token_urlsafe(32)
        state.unlock_token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        state.unlock_expires_at = now + timedelta(minutes=EMAIL_UNLOCK_MINUTES)
    db.session.commit()
    return token


def clear_failed_logins(user):
    state = db.session.get(LoginSecurityState, user.id)
    if state:
        state.failed_attempts = 0
        state.locked_until = None
        state.unlock_token_hash = None
        state.unlock_expires_at = None
        db.session.commit()


def _unlock_state(token, now=None):
    if not isinstance(token, str) or len(token) > 200 or len(token) < 32:
        return None
    now = now or datetime.utcnow()
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    state = db.session.execute(
        db.select(LoginSecurityState).where(LoginSecurityState.unlock_token_hash == digest)
    ).scalar_one_or_none()
    if not state or not state.unlock_token_hash or not state.unlock_expires_at:
        return None
    if not hmac.compare_digest(state.unlock_token_hash, digest):
        return None
    if state.unlock_expires_at <= now or not state.locked_until or state.locked_until <= now:
        return None
    return state


def verify_email_unlock_token(token):
    """GET only validates; email link scanners must never unlock an account."""
    return _unlock_state(token) is not None


def approve_email_unlock(token):
    """POST + CSRF approval consumes token and restores five tries."""
    state = _unlock_state(token)
    if state is None:
        return False
    state.failed_attempts = 0
    state.locked_until = None
    state.unlock_token_hash = None
    state.unlock_expires_at = None
    db.session.commit()
    return True
