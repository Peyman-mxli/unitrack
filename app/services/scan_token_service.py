"""Short-lived, signed, one-use QR tokens for supervised campus scans."""
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from flask import current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.database import db
from app.models.user_model import User
from app.models.scan_token_model import ScanToken

QR_TOKEN_LIFETIME_SECONDS = 300


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="unitrack-qr-v1")


def _extract_token(qr_text):
    text = str(qr_text or "").strip()
    if "scan_token=" in text:
        try:
            return parse_qs(urlparse(text).query).get("scan_token", [""])[0]
        except (ValueError, TypeError):
            return ""
    return text if text.startswith("eyJ") else ""


def issue_scan_token(user):
    """Build a token without recording a reusable static ID in the QR."""
    if not user or not user.is_active_user:
        raise ValueError("An active account is required for QR creation.")
    nonce = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    claim = {
        "uid": user.id,
        "nonce": nonce,
        "version": hashlib.sha256(user.password_hash.encode("utf-8")).hexdigest()[:16],
    }
    token = _serializer().dumps(claim)
    db.session.add(ScanToken(
        user_id=user.id,
        token_hash=hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        issued_at=now,
        expires_at=now + timedelta(seconds=QR_TOKEN_LIFETIME_SECONDS),
    ))
    db.session.commit()
    return token


def resolve_scan_token(qr_text):
    """Validate signature, age, account state and single-use DB record."""
    token = _extract_token(qr_text)
    if not token:
        raise ValueError("Scan an official, signed UniTrack QR code.")
    try:
        payload = _serializer().loads(token, max_age=QR_TOKEN_LIFETIME_SECONDS)
    except SignatureExpired as exc:
        raise ValueError("This QR code has expired. Refresh the QR display.") from exc
    except (BadSignature, TypeError, ValueError) as exc:
        raise ValueError("Invalid QR signature.") from exc

    user_id = payload.get("uid")
    nonce = payload.get("nonce")
    if not isinstance(user_id, int) or not isinstance(nonce, str):
        raise ValueError("Invalid QR data.")
    user = db.session.get(User, user_id)
    if not user or not user.is_active_user:
        raise ValueError("User account is unavailable.")
    current_password_version = hashlib.sha256(user.password_hash.encode("utf-8")).hexdigest()[:16]
    if payload.get("version") != current_password_version:
        raise ValueError("QR code is no longer valid. Refresh it.")
    nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    record = db.session.execute(db.select(ScanToken).where(
        ScanToken.token_hash == nonce_hash, ScanToken.user_id == user.id
    )).scalar_one_or_none()
    if not record or record.consumed_at is not None or record.expires_at < datetime.utcnow():
        raise ValueError("QR code has already been used or has expired.")
    return user, record


def consume_scan_token(record):
    """Atomically mark a QR used to reject repeated/concurrent scans."""
    from sqlalchemy import update
    changed = db.session.execute(
        update(ScanToken)
        .where(ScanToken.id == record.id, ScanToken.consumed_at.is_(None))
        .where(ScanToken.expires_at >= datetime.utcnow())
        .values(consumed_at=datetime.utcnow())
    )
    if changed.rowcount != 1:
        db.session.rollback()
        raise ValueError("QR code has already been used or has expired.")
    db.session.commit()
