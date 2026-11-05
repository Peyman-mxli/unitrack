"""TOTP-based administrator MFA. Uses RFC 6238 compatible authenticator codes.

No paid service: 30-second TOTP, encrypted server-side at rest, one-time
recovery codes. An administrator must enroll using their own authenticator.
"""
import base64
from datetime import datetime
import hashlib
import hmac
from io import BytesIO
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet
from flask import current_app
import qrcode

from app.database import db
from app.models.admin_mfa_model import AdminMFA, AdminMFARecoveryCode


def _fernet():
    secret = str(current_app.config["SECRET_KEY"])
    derived = hashlib.sha256(("unitrack-admin-mfa-v1:" + secret).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def encrypt_secret(secret):
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(encrypted_secret):
    return _fernet().decrypt(encrypted_secret.encode("ascii")).decode("ascii")


def current_totp(secret, counter):
    data = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(data, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1_000_000:06d}"


def verify_totp(secret, code, last_counter=-1, now=None):
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    counter = int(time.time() if now is None else now) // 30
    for candidate in (counter - 1, counter, counter + 1):
        if candidate <= last_counter or candidate < 0:
            continue
        if hmac.compare_digest(current_totp(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret, username):
    account = quote(username, safe="")
    return f"otpauth://totp/UniTrack:{account}?secret={secret}&issuer=UniTrack&algorithm=SHA1&digits=6&period=30"


def provisioning_image_data_uri(uri):
    img = qrcode.make(uri)
    output = BytesIO()
    img.save(output, format="PNG")
    return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")


def generate_recovery_codes():
    raw = [secrets.token_hex(8).upper() for _ in range(8)]
    return [f"{x[:4]}-{x[4:8]}-{x[8:12]}-{x[12:]}" for x in raw]


def recovery_hash(code):
    clean = "".join(c for c in str(code).upper() if c in "0123456789ABCDEF")
    if len(clean) != 16:
        return None
    return hashlib.sha256(("unitrack-mfa-recovery-v1:" + clean).encode("ascii")).hexdigest()


def begin_setup(user_id):
    """Start setup if not already enabled; never rotate a live MFA secret."""
    record = db.session.get(AdminMFA, user_id)
    if record and record.enabled_at is not None:
        return record
    if record is None:
        record = AdminMFA(user_id=user_id, encrypted_secret=encrypt_secret(new_totp_secret()))
        db.session.add(record)
        db.session.commit()
    return record


def confirm_setup(record, code):
    """Verify authenticator setup then store one-use recovery hashes."""
    if record.enabled_at:
        return None
    secret = decrypt_secret(record.encrypted_secret)
    counter = verify_totp(secret, code)
    if counter is None:
        return None
    values = generate_recovery_codes()
    record.enabled_at = datetime.utcnow()
    record.last_counter = counter
    for value in values:
        db.session.add(AdminMFARecoveryCode(
            user_id=record.user_id, code_hash=recovery_hash(value)
        ))
    db.session.commit()
    return values


def authenticate_admin_factor(record, code):
    """Consume one TOTP counter or one recovery code. Replay is not allowed."""
    value = str(code or "").strip()
    if len(value) == 6 and value.isascii() and value.isdigit():
        counter = verify_totp(decrypt_secret(record.encrypted_secret), value, record.last_counter)
        if counter is None:
            return False
        # Use a conditional update so concurrent requests cannot replay a code.
        result = db.session.execute(
            db.update(AdminMFA)
            .where(AdminMFA.user_id == record.user_id, AdminMFA.last_counter < counter)
            .values(last_counter=counter)
        )
        if result.rowcount != 1:
            db.session.rollback()
            return False
        db.session.commit()
        return True

    digest = recovery_hash(value)
    if digest is None:
        return False
    row = db.session.execute(
        db.update(AdminMFARecoveryCode)
        .where(
            AdminMFARecoveryCode.user_id == record.user_id,
            AdminMFARecoveryCode.code_hash == digest,
            AdminMFARecoveryCode.used_at.is_(None)
        )
        .values(used_at=datetime.utcnow())
    )
    if row.rowcount != 1:
        db.session.rollback()
        return False
    db.session.commit()
    return True
