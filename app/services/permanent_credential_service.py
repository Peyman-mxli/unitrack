"""Stable, revocable QR credentials for the four permanent UniTrack roles."""
from datetime import datetime
import hashlib
import hmac

from flask import current_app
from itsdangerous import URLSafeSerializer, BadSignature

from app.database import db
from app.models.user_model import User
from app.models.permanent_credential_model import PermanentCredential, CredentialReplacementRequest

ROLES = {"estudiante": "EST", "docente": "DOC", "personal": "PER", "administrativo": "ADM"}
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _secret():
    return str(current_app.config["SECRET_KEY"]).encode("utf-8")


def _code(user, generation):
    prefix = ROLES[user.role]
    digest = hmac.new(_secret(), f"unitrack-permanent-v1:{user.id}:{generation}:{prefix}".encode(), hashlib.sha256).digest()
    # Take 5-bit chunks from the first 10 bytes; 80 bits of unpredictable code.
    value = int.from_bytes(digest[:10], "big")
    letters = "".join(ALPHABET[(value >> shift) & 31] for shift in range(75, -1, -5))
    return prefix + "-" + "-".join(letters[i:i + 4] for i in range(0, 16, 4))


def _hash_code(code):
    return hashlib.sha256(code.upper().encode("ascii")).hexdigest()


def _serializer():
    return URLSafeSerializer(current_app.config["SECRET_KEY"], salt="unitrack-permanent-qr-v1")


def get_or_create_credential(user):
    if not user or not user.is_active_user or user.role not in ROLES:
        raise ValueError("An active permanent university account is required.")
    record = db.session.get(PermanentCredential, user.id)
    if record is None:
        record = PermanentCredential(user_id=user.id, generation=1,
                                     code_hash=_hash_code(_code(user, 1)))
        db.session.add(record)
        db.session.commit()
    return record


def permanent_credential_for_user(user):
    """Returns a stable signed QR token and stable fallback code, across refreshes."""
    record = get_or_create_credential(user)
    token = "P." + _serializer().dumps({"uid": user.id, "gen": record.generation})
    return token, _code(user, record.generation)


def resolve_permanent_credential(value):
    """Return (active user, credential) or raise ValueError. Never trust raw user IDs."""
    raw = str(value or "").strip()
    if "scan_token=" in raw:
        from urllib.parse import urlparse, parse_qs
        raw = parse_qs(urlparse(raw).query).get("scan_token", [""])[0]
    if raw.startswith("P."):
        try:
            data = _serializer().loads(raw[2:])
        except (BadSignature, ValueError, TypeError) as exc:
            raise ValueError("Invalid permanent QR signature.") from exc
        if not isinstance(data, dict) or not isinstance(data.get("uid"), int) or not isinstance(data.get("gen"), int):
            raise ValueError("Malformed permanent QR.")
        record = db.session.get(PermanentCredential, data["uid"])
        if record is None or record.generation != data["gen"]:
            raise ValueError("This QR was replaced or revoked.")
    else:
        normalized = raw.upper().replace(" ", "")
        if not (len(normalized) == 23 and normalized[:3] in ROLES.values()
                and normalized[3] == "-" and
                all(c in ALPHABET for c in normalized[4:].replace("-", ""))
                and normalized.count("-") == 4):
            raise ValueError("Invalid permanent access code.")
        record = db.session.execute(db.select(PermanentCredential).where(
            PermanentCredential.code_hash == _hash_code(normalized)
        )).scalar_one_or_none()
        if record is None:
            raise ValueError("Unknown or revoked permanent access code.")
    user = db.session.get(User, record.user_id)
    if not user or not user.is_active_user or user.role not in ROLES:
        raise ValueError("Permanent account is inactive or unavailable.")
    if not hmac.compare_digest(record.code_hash, _hash_code(_code(user, record.generation))):
        raise ValueError("Permanent access credential is no longer valid.")
    return user, record


def is_permanent_credential(value):
    raw = str(value or "").strip()
    if "scan_token=" in raw:
        from urllib.parse import urlparse, parse_qs
        raw = parse_qs(urlparse(raw).query).get("scan_token", [""])[0]
    if raw.startswith("P."):
        return True
    # Legacy 5-minute codes deliberately share EST-/DOC-/PER-/ADM- prefixes.
    # Distinguish by the persisted digest, not by prefix, so old sessions keep
    # working until those short-lived credentials expire naturally.
    normalized = raw.upper().replace(" ", "")
    if not normalized.startswith(tuple(prefix + "-" for prefix in ROLES.values())):
        return False
    return db.session.execute(db.select(PermanentCredential.user_id).where(
        PermanentCredential.code_hash == _hash_code(normalized)
    )).first() is not None

def request_replacement(user, reason):
    if user.role not in ROLES:
        raise ValueError("Only permanent university users can request replacement.")
    reason = str(reason or "").strip()
    if not 8 <= len(reason) <= 300:
        raise ValueError("Explain why you need a new QR (8 to 300 characters).")
    pending = db.session.execute(db.select(CredentialReplacementRequest).where(
        CredentialReplacementRequest.user_id == user.id,
        CredentialReplacementRequest.status == "pending"
    )).scalar_one_or_none()
    if pending:
        raise ValueError("You already have a pending QR replacement request.")
    db.session.add(CredentialReplacementRequest(user_id=user.id, reason=reason))
    db.session.commit()


def review_replacement(request_id, admin, approve):
    if admin.role != "administrativo":
        raise ValueError("Only administrators can approve QR replacements.")
    item = db.session.get(CredentialReplacementRequest, request_id)
    if item is None or item.status != "pending":
        raise ValueError("Request is already reviewed or does not exist.")
    if approve:
        user = db.session.get(User, item.user_id)
        credential = get_or_create_credential(user)
        credential.generation += 1
        credential.code_hash = _hash_code(_code(user, credential.generation))
        credential.replaced_at = datetime.utcnow()
    item.status = "approved" if approve else "rejected"
    item.reviewed_at = datetime.utcnow()
    item.reviewed_by = admin.id
    db.session.commit()
    return item
