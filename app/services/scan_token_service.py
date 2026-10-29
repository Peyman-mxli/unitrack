"""Signed, per-person QR credentials with matching one-time manual access codes.

Both QR and backup code resolve to the SAME ScanToken record and expire/are
consumed together. A permanent public user ID cannot grant campus access.
"""
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from flask import current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.database import db
from app.models.user_model import User
from app.models.scan_token_model import ScanToken

QR_TOKEN_LIFETIME_SECONDS = 300
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_LENGTH = 16


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


def _normalize_code(value):
    text = str(value or "").strip().upper().replace("-", "").replace(" ", "")
    if len(text) != _CODE_LENGTH or any(c not in _CODE_ALPHABET for c in text):
        return ""
    return text


def issue_access_credential(user):
    """Issue one short-lived QR token and matching 16-character manual code.

    The DB only stores the code hash, not the plaintext. Both consume the
    same record, so one successful scan invalidates the other method.
    """
    if not user or not user.is_active_user:
        raise ValueError("An active account is required for QR creation.")

    now = datetime.utcnow()
    # Collision-resistant random 80-bit code; never use predictable user IDs.
    for _ in range(5):
        nonce = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
        digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        if not db.session.execute(db.select(ScanToken.id).where(
            ScanToken.token_hash == digest
        )).first():
            break
    else:
        raise RuntimeError("Unable to create unique access code.")

    token = _serializer().dumps({
        "uid": user.id,
        "nonce": nonce,
        "version": hashlib.sha256(user.password_hash.encode("utf-8")).hexdigest()[:16],
    })
    db.session.add(ScanToken(
        user_id=user.id,
        token_hash=digest,
        issued_at=now,
        expires_at=now + timedelta(seconds=QR_TOKEN_LIFETIME_SECONDS),
    ))
    db.session.commit()
    readable_code = "-".join(nonce[i:i + 4] for i in range(0, _CODE_LENGTH, 4))
    return token, readable_code


def issue_scan_token(user):
    """Compatibility helper for callers that only need a signed QR."""
    token, _backup_code = issue_access_credential(user)
    return token


def resolve_scan_token(qr_text):
    """Identify and verify a signed QR OR its matching temporary backup code."""
    supplied = str(qr_text or "").strip()
    nonce_from_code = _normalize_code(supplied)
    now = datetime.utcnow()
    if nonce_from_code:
        digest = hashlib.sha256(nonce_from_code.encode("ascii")).hexdigest()
        record = db.session.execute(db.select(ScanToken).where(
            ScanToken.token_hash == digest
        )).scalar_one_or_none()
        if not record or record.consumed_at is not None or record.expires_at < now:
            raise ValueError("Access code has already been used or has expired.")
        user = db.session.get(User, record.user_id)
        if not user or not user.is_active_user:
            raise ValueError("User account is unavailable.")
        return user, record

    token = _extract_token(supplied)
    if not token:
        raise ValueError("Scan a signed QR or enter a valid temporary access code.")
    try:
        payload = _serializer().loads(token, max_age=QR_TOKEN_LIFETIME_SECONDS)
    except SignatureExpired as exc:
        raise ValueError("This QR code has expired. Refresh the QR display.") from exc
    except (BadSignature, TypeError, ValueError) as exc:
        raise ValueError("Invalid QR signature.") from exc

    if not isinstance(payload, dict):
        raise ValueError("Invalid QR data.")
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
    if not record or record.consumed_at is not None or record.expires_at < now:
        raise ValueError("QR code has already been used or has expired.")
    return user, record


def consume_scan_token(record):
    """Mark the credential used in the same transaction as check-in/out."""
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
    db.session.flush()
