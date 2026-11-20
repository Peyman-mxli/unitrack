"""Admin-approved temporary visitor QR passes and recorded campus movements."""
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets

from flask import current_app
from itsdangerous import URLSafeSerializer, BadSignature
from app.database import db
from app.models.user_model import User
from app.models.visitor_access_model import VisitorPass, VisitorRequest, VisitorAccessLog
from app.utils.local_time import campus_now

MAX_PASS_DAYS = 366
MAX_REQUEST_DAYS = 90


def parse_period(start, end):
    try:
        starts = datetime.fromisoformat(str(start))
        expires = datetime.fromisoformat(str(end))
    except (ValueError, TypeError) as exc:
        raise ValueError("Enter valid start and expiration dates/times.") from exc
    if starts.tzinfo is not None or expires.tzinfo is not None:
        raise ValueError("Use local campus times without a timezone offset.")
    if expires <= starts or expires - starts > timedelta(days=MAX_PASS_DAYS):
        raise ValueError("Expiration must be later than start, within one year.")
    return starts, expires


def issue_visitor_pass(admin, full_name, purpose, start, end, email="", linked_user=None):
    if admin.role != "administrativo" or not admin.is_active_user:
        raise ValueError("Only an active administrator can issue visitor passes.")
    starts, expires = parse_period(start, end)
    if expires <= campus_now():
        raise ValueError("The visitor pass must expire in the future.")
    full_name, purpose, email = (str(full_name or "").strip(),
                               str(purpose or "").strip(), str(email or "").strip())
    if not 2 <= len(full_name) <= 180 or not 3 <= len(purpose) <= 300 or len(email) > 160:
        raise ValueError("Provide valid visitor name, purpose and optional email.")
    if linked_user is not None and (linked_user.role != "visitante" or not linked_user.is_active_user):
        raise ValueError("Linked visitor account is inactive or invalid.")
    item = VisitorPass(
        full_name=full_name, purpose=purpose, email=email, issued_by=admin.id,
        linked_user_id=linked_user.id if linked_user else None,
        nonce=secrets.token_urlsafe(24), starts_at=starts, expires_at=expires,
    )
    db.session.add(item)
    db.session.commit()
    return item


def _serializer():
    return URLSafeSerializer(current_app.config["SECRET_KEY"], salt="unitrack-visitor-qr-v1")


def visitor_token(pass_record):
    return "V." + _serializer().dumps({"id": pass_record.id, "nonce": pass_record.nonce})


def visitor_code(pass_record):
    material = hmac.new(str(current_app.config["SECRET_KEY"]).encode(),
                        f"visitor:{pass_record.id}:{pass_record.nonce}".encode(),
                        hashlib.sha256).digest()
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    bits = int.from_bytes(material[:10], "big")
    letters = "".join(alphabet[(bits >> shift) & 31] for shift in range(75, -1, -5))
    return "VIS-" + "-".join(letters[i:i+4] for i in range(0, 16, 4))


def is_visitor_credential(text):
    raw = str(text or "").strip()
    if "scan_token=" in raw:
        from urllib.parse import parse_qs, urlparse
        raw = parse_qs(urlparse(raw).query).get("scan_token", [""])[0]
    return raw.startswith("V.") or raw.upper().startswith("VIS-")


def resolve_visitor_pass(text):
    raw = str(text or "").strip()
    if "scan_token=" in raw:
        from urllib.parse import parse_qs, urlparse
        raw = parse_qs(urlparse(raw).query).get("scan_token", [""])[0]
    if raw.startswith("V."):
        try:
            payload = _serializer().loads(raw[2:])
        except (BadSignature, ValueError, TypeError) as exc:
            raise ValueError("Invalid visitor QR signature.") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("id"), int):
            raise ValueError("Invalid visitor QR.")
        item = db.session.get(VisitorPass, payload["id"])
        if not item or not hmac.compare_digest(item.nonce, str(payload.get("nonce", ""))):
            raise ValueError("Visitor QR was revoked or is invalid.")
    elif raw.upper().startswith("VIS-"):
        # No raw name/ID is ever accepted as a guest credential.
        # The short code is 80-bit unpredictable and matched in constant time.
        normalized = raw.upper().replace(" ", "")
        item = None
        for candidate in db.session.execute(db.select(VisitorPass).where(
            VisitorPass.revoked_at.is_(None),
            VisitorPass.expires_at >= campus_now() - timedelta(days=1)
        )).scalars():
            if hmac.compare_digest(visitor_code(candidate), normalized):
                item = candidate
                break
        if item is None:
            raise ValueError("Unknown visitor code.")
    else:
        raise ValueError("Invalid visitor credential.")
    if item.revoked_at is not None:
        raise ValueError("This visitor permission was revoked.")
    if item.linked_user_id is not None:
        user = db.session.get(User, item.linked_user_id)
        if not user or user.role != "visitante" or not user.is_active_user:
            raise ValueError("Visitor account is inactive.")
    return item


def scan_visitor(text):
    """Only called by the authenticated operator scanner."""
    item = resolve_visitor_pass(text)
    now = campus_now()
    open_log = db.session.execute(db.select(VisitorAccessLog).where(
        VisitorAccessLog.pass_id == item.id, VisitorAccessLog.checked_out_at.is_(None)
    ).order_by(VisitorAccessLog.id.desc())).scalars().first()
    if open_log:
        if (now - open_log.checked_in_at).total_seconds() < 2:
            raise ValueError("Entry recorded. Wait before recording an exit.")
        open_log.checked_out_at = now
        action = "check_out"
        event = open_log
    else:
        if not item.starts_at <= now < item.expires_at:
            raise ValueError("Visitor permission is not active at this date/time.")
        latest = db.session.execute(db.select(VisitorAccessLog).where(
            VisitorAccessLog.pass_id == item.id
        ).order_by(VisitorAccessLog.id.desc())).scalars().first()
        if latest and latest.checked_out_at and (now - latest.checked_out_at).total_seconds() < 2:
            raise ValueError("Exit recorded. Wait before recording a new entry.")
        event = VisitorAccessLog(pass_id=item.id, checked_in_at=now)
        db.session.add(event)
        action = "check_in"
    db.session.commit()
    return {
        "success": True, "action": action, "user_name": item.full_name,
        "role": "visitante", "username": item.email or "Invitado",
        "message": "Visitor entry recorded." if action == "check_in" else "Visitor exit recorded.",
        "check_in_time": event.checked_in_at.isoformat(),
        "check_out_time": event.checked_out_at.isoformat() if event.checked_out_at else None,
    }


def request_visitor_access(user, purpose, start, end):
    if user.role != "visitante" or not user.is_active_user:
        raise ValueError("Only registered visitors can request visitor access.")
    starts, expires = parse_period(start, end)
    if expires <= campus_now() or expires - starts > timedelta(days=MAX_REQUEST_DAYS):
        raise ValueError("Request a future access period up to 90 days.")
    purpose = str(purpose or "").strip()
    if not 3 <= len(purpose) <= 300:
        raise ValueError("Explain the visit purpose (3 to 300 characters).")
    pending = db.session.execute(db.select(VisitorRequest).where(
        VisitorRequest.user_id == user.id, VisitorRequest.status == "pending"
    )).scalar_one_or_none()
    if pending:
        raise ValueError("A visitor request is already awaiting approval.")
    item = VisitorRequest(user_id=user.id, purpose=purpose,
                          desired_start=starts, desired_end=expires)
    db.session.add(item)
    db.session.commit()
    return item


def review_visitor_request(request_id, admin, approve, start=None, end=None):
    if admin.role != "administrativo" or not admin.is_active_user:
        raise ValueError("Administrator approval required.")
    item = db.session.get(VisitorRequest, request_id)
    if item is None or item.status != "pending":
        raise ValueError("Request does not exist or is already reviewed.")
    user = db.session.get(User, item.user_id)
    if user is None or user.role != "visitante" or not user.is_active_user:
        raise ValueError("Visitor account is inactive.")
    if approve:
        issue_visitor_pass(
            admin, user.full_name(), item.purpose,
            start or item.desired_start.isoformat(timespec="minutes"),
            end or item.desired_end.isoformat(timespec="minutes"),
            email=user.email, linked_user=user,
        )
    item.status = "approved" if approve else "rejected"
    item.reviewed_by = admin.id
    item.reviewed_at = datetime.utcnow()
    db.session.commit()
    return item
