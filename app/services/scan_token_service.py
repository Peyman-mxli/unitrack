"""Signed per-person QR and backup codes for paired entrance/exit scans.

Unused credentials expire after five minutes. After an authorized first
check-in, the SAME signed credential can check out its matching entry once
within 24 hours, then is permanently closed. Permanent IDs remain invalid.
"""
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
QR_CHECKOUT_LIFETIME_SECONDS = 24 * 60 * 60
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_LENGTH = 16
# Every person receives a random secret, plus a visible three-letter role.
_ROLE_PREFIX = {
    "estudiante": "EST", "student": "EST",
    "docente": "DOC", "professor": "DOC", "teacher": "DOC",
    "personal": "PER", "staff": "PER",
    "administrativo": "ADM", "admin": "ADM",
}
_VALID_PREFIXES = frozenset((*_ROLE_PREFIX.values(), "USR"))


def _prefix_for_user(user):
    return _ROLE_PREFIX.get(str(getattr(user, "role", "") or "").lower(), "USR")


def _nonce_matches_role(nonce, user):
    # Previously issued no-prefix credentials are valid until expiry.
    prefix, separator, _secret = nonce.partition(":")
    return not separator or prefix == _prefix_for_user(user)



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
    """Normalize role-prefixed codes to the exact nonce used by the QR.

    New: DOC-ABCD-EFGH-JKLM-NPQR -> DOC:ABCDEFGHJKLMNPQR
    Old: ABCD-EFGH-JKLM-NPQR -> ABCDEFGHJKLMNPQR
    The former cannot be used by changing or removing the prefix.
    """
    text = str(value or "").strip().upper().replace("-", "").replace(" ", "")
    if len(text) == _CODE_LENGTH:
        secret = text  # existing short-lived credentials from previous version
        prefix = ""
    elif len(text) == _CODE_LENGTH + 3:
        prefix, secret = text[:3], text[3:]
        if prefix not in _VALID_PREFIXES:
            return ""
    else:
        return ""
    if any(c not in _CODE_ALPHABET for c in secret):
        return ""
    return f"{prefix}:{secret}" if prefix else secret


def issue_access_credential(user):
    """Create a unique QR and matching manual code for the account.

    The first scan must occur within five minutes. After check-in the same
    credential can complete its paired checkout once within 24 hours.
    """
    if not user or not user.is_active_user:
        raise ValueError("An active account is required for QR creation.")

    now = datetime.utcnow()
    # Collision-resistant random 80-bit code; never use predictable user IDs.
    prefix = _prefix_for_user(user)
    for _ in range(5):
        secret = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
        nonce = f"{prefix}:{secret}"
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
    readable_code = prefix + "-" + "-".join(
        secret[i:i + 4] for i in range(0, _CODE_LENGTH, 4)
    )
    return token, readable_code


def issue_scan_token(user):
    """Compatibility helper for callers that only need a signed QR."""
    token, _backup_code = issue_access_credential(user)
    return token


def is_temporary_access_code(value):
    return bool(_normalize_code(value))


def _check_credential_state(record, now):
    """Reject used/expired codes unless they have an open paired entry."""
    if not record:
        raise ValueError("Invalid QR or temporary access code.")
    if record.consumed_at is None:
        if record.expires_at < now:
            raise ValueError("This QR or temporary code has expired. Generate a new one.")
        return

    from app.models.access_scan_pair_model import AccessScanPair
    from app.models.access_log_model import AccessLog
    pair = db.session.execute(
        db.select(AccessScanPair).where(AccessScanPair.scan_token_id == record.id)
    ).scalar_one_or_none()
    if not pair or pair.checked_out_at is not None or pair.user_id != record.user_id:
        raise ValueError("QR code has already been used. Generate a new one.")
    if record.issued_at < now - timedelta(seconds=QR_CHECKOUT_LIFETIME_SECONDS):
        raise ValueError("The checkout QR has expired. Generate a new one.")
    entry = db.session.get(AccessLog, pair.access_log_id)
    if not entry or entry.student_id != record.user_id or entry.check_out_time is not None:
        raise ValueError("This QR's corresponding entry is already closed.")


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
        _check_credential_state(record, now)
        user = db.session.get(User, record.user_id)
        if not user or not user.is_active_user:
            raise ValueError("User account is unavailable.")
        if not _nonce_matches_role(nonce_from_code, user):
            raise ValueError("Access code no longer matches the user's role.")
        return user, record

    token = _extract_token(supplied)
    if not token:
        raise ValueError("Scan a signed QR or enter a valid temporary access code.")
    try:
        payload = _serializer().loads(token, max_age=QR_CHECKOUT_LIFETIME_SECONDS)
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
    if not _nonce_matches_role(nonce, user):
        raise ValueError("QR code no longer matches the user's role. Refresh it.")
    nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    record = db.session.execute(db.select(ScanToken).where(
        ScanToken.token_hash == nonce_hash, ScanToken.user_id == user.id
    )).scalar_one_or_none()
    _check_credential_state(record, now)
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
