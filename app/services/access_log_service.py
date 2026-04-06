"""
access_log_service.py

Independent business logic for UniTrack university access control.
"""

from datetime import datetime
from urllib.parse import urlparse, parse_qs
import hashlib

from app.database import db
from app.models.access_log_model import AccessLog
from app.models.user_model import User


ALLOWED_ACCESS_ROLES = {"estudiante", "personal", "administrativo", "docente", "professor"}


def get_current_system_datetime():
    """
    Return the real current local server datetime.

    Why this fix exists:
    The previous code used datetime.utcnow(), which can make the UI show
    shifted or seemingly random hours if your app/server/display expects
    local time. Using datetime.now() keeps check-in/check-out timestamps
    aligned with the real local time used by the app.
    """
    return datetime.now()


def normalize_access_role(role_value):
    return (role_value or "").strip().lower()


def is_access_role_allowed(role_value):
    return normalize_access_role(role_value) in ALLOWED_ACCESS_ROLES


def get_user_by_id_for_access(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return None
    if not is_access_role_allowed(getattr(user, "role", None)):
        return None
    return user


def get_student_by_id(student_id):
    return get_user_by_id_for_access(student_id)


def get_personal_by_id(personal_id):
    user = db.session.get(User, personal_id)
    if not user:
        return None
    if normalize_access_role(getattr(user, "role", None)) not in {"personal", "administrativo"}:
        return None
    return user


def get_access_user_by_id_code(user_id_code):
    if not user_id_code:
        return None

    normalized_code = (user_id_code or "").strip()
    if not normalized_code:
        return None

    query = db.select(User).filter(User.user_id_code == normalized_code)
    user = db.session.execute(query).scalars().first()

    if not user:
        return None

    if not is_access_role_allowed(getattr(user, "role", None)):
        return None

    return user


def build_access_short_qr_id_code(user):
    """
    Build the same short fallback QR ID code format already used in the UI,
    for example: 03DC66
    """
    raw_text = (
        f"{getattr(user, 'id', '')}|"
        f"{getattr(user, 'username', '')}|"
        f"{getattr(user, 'first_name', '')}|"
        f"{getattr(user, 'last_name', '')}"
    )
    digest = hashlib.sha1(raw_text.encode("utf-8")).hexdigest().upper()

    first_two_digits = str(getattr(user, "id", 0)).zfill(2)[-2:]

    letters_pool = "".join([char for char in digest if char.isalpha()])
    two_letters = letters_pool[:2] if len(letters_pool) >= 2 else "QR"

    username_value = str(getattr(user, "username", "") or "")
    user_id_value = int(getattr(user, "id", 0) or 0)
    last_two_digits = str((len(username_value) * 7 + user_id_value) % 100).zfill(2)

    return f"{first_two_digits}{two_letters}{last_two_digits}"


def get_access_user_by_short_qr_id_code(qr_id_code):
    if not qr_id_code:
        return None

    normalized_code = str(qr_id_code or "").strip().upper()
    if not normalized_code:
        return None

    query = db.select(User)
    users = db.session.execute(query).scalars().all()

    for user in users:
        if not is_access_role_allowed(getattr(user, "role", None)):
            continue

        candidate_code = build_access_short_qr_id_code(user).upper()
        if candidate_code == normalized_code:
            return user

    return None


def get_open_access_log_for_user(user_id):
    query = (
        db.select(AccessLog)
        .filter(
            AccessLog.student_id == user_id,
            AccessLog.check_out_time.is_(None),
            AccessLog.access_status == "checked_in"
        )
        .order_by(AccessLog.check_in_time.desc())
    )
    return db.session.execute(query).scalars().first()


def get_open_access_log_for_student(student_id):
    return get_open_access_log_for_user(student_id)


def get_open_access_log_for_personal(personal_id):
    return get_open_access_log_for_user(personal_id)


def get_latest_access_log_for_user(user_id):
    query = (
        db.select(AccessLog)
        .filter(AccessLog.student_id == user_id)
        .order_by(AccessLog.check_in_time.desc())
    )
    return db.session.execute(query).scalars().first()


def get_latest_access_log_for_student(student_id):
    return get_latest_access_log_for_user(student_id)


def get_latest_access_log_for_personal(personal_id):
    return get_latest_access_log_for_user(personal_id)


def calculate_minutes_between(check_in_time, check_out_time):
    if not check_in_time or not check_out_time:
        return 0
    delta = check_out_time - check_in_time
    total_seconds = int(delta.total_seconds())
    if total_seconds <= 0:
        return 0
    return total_seconds // 60


def calculate_minutes_until_now(check_in_time):
    if not check_in_time:
        return 0
    now = get_current_system_datetime()
    delta = now - check_in_time
    total_seconds = int(delta.total_seconds())
    if total_seconds <= 0:
        return 0
    return total_seconds // 60


def create_check_in(student_id=None, personal_id=None, access_method="qr", notes=None):
    user_id = student_id if student_id is not None else personal_id

    if user_id is None:
        raise ValueError("User id is required")

    user = get_user_by_id_for_access(user_id)

    if not user:
        raise ValueError("User not found or role is not allowed for access control")

    existing_open_log = get_open_access_log_for_user(user_id)

    if existing_open_log:
        raise ValueError("User already has an active check-in")

    now = get_current_system_datetime()

    new_log = AccessLog(
        student_id=user_id,
        access_date=now.date(),
        check_in_time=now,
        check_out_time=None,
        access_status="checked_in",
        access_method=access_method,
        notes=notes
    )

    try:
        db.session.add(new_log)
        db.session.commit()
        return new_log
    except Exception:
        db.session.rollback()
        raise


def create_check_out(student_id=None, personal_id=None, notes=None):
    user_id = student_id if student_id is not None else personal_id

    if user_id is None:
        raise ValueError("User id is required")

    user = get_user_by_id_for_access(user_id)

    if not user:
        raise ValueError("User not found or role is not allowed for access control")

    open_log = get_open_access_log_for_user(user_id)

    if not open_log:
        raise ValueError("User does not have an active check-in")

    now = get_current_system_datetime()

    open_log.check_out_time = now
    open_log.access_status = "checked_out"

    if notes:
        open_log.notes = notes

    if hasattr(open_log, "updated_at"):
        open_log.updated_at = now

    try:
        db.session.commit()
        return open_log
    except Exception:
        db.session.rollback()
        raise


def _extract_code_from_qr_value(qr_value):
    if not qr_value:
        return ""

    normalized_value = str(qr_value).strip()
    if not normalized_value:
        return ""

    if normalized_value.startswith("http://") or normalized_value.startswith("https://") or normalized_value.startswith("/"):
        try:
            parsed_url = urlparse(normalized_value)
            query_values = parse_qs(parsed_url.query)

            user_code = str(query_values.get("user_code", [""])[0]).strip()
            qr_id_code = str(query_values.get("qr_id_code", [""])[0]).strip()
            qr_text_from_url = str(query_values.get("qr_text", [""])[0]).strip()

            if user_code:
                return user_code

            if qr_id_code:
                return qr_id_code

            if qr_text_from_url:
                return _extract_code_from_qr_value(qr_text_from_url)

        except Exception:
            return normalized_value

    return normalized_value


def process_access_scan(qr_text, access_method="qr", notes=None):
    qr_value = _extract_code_from_qr_value(qr_text)

    if not qr_value:
        raise ValueError("QR value is required")

    resolved_user = None

    if qr_value.startswith("UNITRACK|ACCESS|"):
        parts = qr_value.split("|")
        payload = {}

        for part in parts[2:]:
            if "=" in part:
                key, value = part.split("=", 1)
                payload[key.strip()] = value.strip()

        student_id_value = payload.get("student_id")
        professor_id_value = payload.get("professor_id")
        personal_id_value = payload.get("personal_id")
        admin_id_value = payload.get("admin_id")

        candidate_id_value = (
            student_id_value
            or professor_id_value
            or personal_id_value
            or admin_id_value
        )

        if candidate_id_value and candidate_id_value.isdigit():
            resolved_user = get_user_by_id_for_access(int(candidate_id_value))

    if resolved_user is None:
        resolved_user = get_access_user_by_id_code(qr_value)

    if resolved_user is None:
        resolved_user = get_access_user_by_short_qr_id_code(qr_value)

    if resolved_user is None and qr_value.isdigit():
        resolved_user = get_user_by_id_for_access(int(qr_value))

    if resolved_user is None:
        raise ValueError("QR code is invalid or user was not found")

    open_log = get_open_access_log_for_user(resolved_user.id)

    if open_log:
        log = create_check_out(
            student_id=resolved_user.id,
            notes=notes,
        )
        action = "check_out"
        status = "checked_out"
    else:
        log = create_check_in(
            student_id=resolved_user.id,
            access_method=access_method,
            notes=notes,
        )
        action = "check_in"
        status = "checked_in"

    display_name = build_access_display_name(resolved_user)

    return {
        "success": True,
        "message": "QR processed successfully.",
        "action": action,
        "user_id": resolved_user.id,
        "user_role": normalize_access_role(getattr(resolved_user, "role", None)),
        "student_name": display_name,
        "staff_name": display_name,
        "professor_name": display_name,
        "admin_name": display_name,
        "username": getattr(resolved_user, "username", "") or "--",
        "status": status,
        "check_in_time": format_time_for_display(log.check_in_time),
        "check_out_time": format_time_for_display(log.check_out_time),
    }


def format_minutes_as_hours_text(total_minutes):
    if total_minutes <= 0:
        return "0h 0m"

    hours = total_minutes // 60
    minutes = total_minutes % 60

    return f"{hours}h {minutes}m"


def calculate_hours_text(check_in_time, check_out_time):
    if not check_in_time:
        return "0h 0m"

    if not check_out_time:
        running_minutes = calculate_minutes_until_now(check_in_time)
        return f"In progress · {format_minutes_as_hours_text(running_minutes)}"

    total_minutes = calculate_minutes_between(check_in_time, check_out_time)
    return format_minutes_as_hours_text(total_minutes)


def format_time_for_display(value):
    if not value:
        return "--"
    return value.strftime("%I:%M %p")


def format_date_for_display(value):
    if not value:
        return "--"
    return value.strftime("%m/%d/%Y")


def build_access_display_name(user):
    if not user:
        return "--"

    first = (getattr(user, "first_name", "") or "").strip()
    last = (getattr(user, "last_name", "") or "").strip()
    full = f"{first} {last}".strip()

    if full:
        return full

    username = (getattr(user, "username", "") or "").strip()
    if username:
        return username

    return "User"


def get_user_access_logs(user_id, access_date=None):
    query = db.select(AccessLog).filter(AccessLog.student_id == user_id)

    if access_date:
        query = query.filter(AccessLog.access_date == access_date)

    query = query.order_by(AccessLog.check_in_time.desc())

    return db.session.execute(query).scalars().all()


def get_student_access_logs(student_id, access_date=None):
    return get_user_access_logs(student_id, access_date)


def build_access_table_rows(user):
    logs = get_user_access_logs(user.id)

    rows = []

    display_name = build_access_display_name(user)

    for index, log in enumerate(logs, start=1):
        check_in_display = format_time_for_display(log.check_in_time)
        check_out_display = format_time_for_display(log.check_out_time)
        hours_display = calculate_hours_text(log.check_in_time, log.check_out_time)
        status_display = getattr(log, "access_status", "") or "--"
        access_method_display = getattr(log, "access_method", "") or "--"
        notes_display = getattr(log, "notes", "") or "--"

        rows.append(
            {
                "row": index,
                "name": display_name,
                "matricula": getattr(user, "username", "") or "--",
                "class_name": "University Access",
                "date": format_date_for_display(log.access_date),

                # Original keys
                "check_in": check_in_display,
                "check_out": check_out_display,
                "hours": hours_display,
                "status": status_display,

                # Compatibility keys used by admin/student/staff/professor templates
                "check_in_time": check_in_display,
                "check_out_time": check_out_display,
                "total_hours": hours_display,
                "access_method": access_method_display,
                "notes": notes_display,
            }
        )

    return rows


def build_student_access_table_rows(student):
    return build_access_table_rows(student)


def get_user_access_quick_stats(user_id):
    logs = get_user_access_logs(user_id)
    open_log = get_open_access_log_for_user(user_id)

    total_entries = len(logs)
    total_exits = len([log for log in logs if log.check_out_time])

    return {
        "total_entries": total_entries,
        "total_exits": total_exits,
        "inside_count": 1 if open_log else 0,
        "outside_count": 0 if open_log else 1,
    }


def get_student_access_quick_stats(student_id):
    return get_user_access_quick_stats(student_id)


def get_user_current_access_status(user_id):
    open_log = get_open_access_log_for_user(user_id)
    latest_log = get_latest_access_log_for_user(user_id)

    if open_log:
        check_in_display = format_time_for_display(open_log.check_in_time)
        hours_display = calculate_hours_text(open_log.check_in_time, None)

        return {
            "status": "checked_in",
            "label": "Inside campus",
            "is_inside": True,
            "last_check_in": check_in_display,
            "last_check_out": "--",
            "hours_today": hours_display,

            # Compatibility keys for templates
            "check_in_time": check_in_display,
            "check_out_time": "--",
            "total_hours": hours_display,
        }

    if latest_log:
        check_in_display = format_time_for_display(latest_log.check_in_time)
        check_out_display = format_time_for_display(latest_log.check_out_time)
        hours_display = calculate_hours_text(latest_log.check_in_time, latest_log.check_out_time)

        return {
            "status": "checked_out",
            "label": "Outside campus",
            "is_inside": False,
            "last_check_in": check_in_display,
            "last_check_out": check_out_display,
            "hours_today": hours_display,

            # Compatibility keys for templates
            "check_in_time": check_in_display,
            "check_out_time": check_out_display,
            "total_hours": hours_display,
        }

    return {
        "status": "checked_out",
        "label": "Outside campus",
        "is_inside": False,
        "last_check_in": "--",
        "last_check_out": "--",
        "hours_today": "--",

        # Compatibility keys for templates
        "check_in_time": "--",
        "check_out_time": "--",
        "total_hours": "--",
    }


def get_student_current_access_status(student_id):
    return get_user_current_access_status(student_id)


def get_all_active_access_logs():
    """
    Get all users currently checked-in (inside campus).
    """
    query = (
        db.select(AccessLog)
        .filter(
            AccessLog.check_out_time.is_(None),
            AccessLog.access_status == "checked_in"
        )
        .order_by(AccessLog.check_in_time.desc())
    )
    return db.session.execute(query).scalars().all()


def get_all_active_users():
    """
    Return all active users with readable info for admin dashboard.
    """
    logs = get_all_active_access_logs()
    results = []

    for log in logs:
        user = db.session.get(User, log.student_id)
        if not user:
            continue

        results.append(
            {
                "user_id": getattr(user, "id", None),
                "name": build_access_display_name(user),
                "username": getattr(user, "username", "") or "--",
                "role": normalize_access_role(getattr(user, "role", "")),
                "role_label": _role_label_for_dashboard(getattr(user, "role", "")),
                "check_in_time": format_time_for_display(log.check_in_time),
                "check_out_time": format_time_for_display(log.check_out_time),
                "status": getattr(log, "access_status", "") or "checked_in",
                "user_id_code": getattr(user, "user_id_code", "") or "--",
            }
        )

    return results


def get_today_access_logs():
    """
    Get all access logs for today with dashboard-friendly values.
    """
    today = get_current_system_datetime().date()

    query = (
        db.select(AccessLog)
        .filter(AccessLog.access_date == today)
        .order_by(AccessLog.check_in_time.desc())
    )

    logs = db.session.execute(query).scalars().all()
    results = []

    for index, log in enumerate(logs, start=1):
        user = db.session.get(User, log.student_id)
        if not user:
            continue

        check_in_display = format_time_for_display(log.check_in_time)
        check_out_display = format_time_for_display(log.check_out_time)
        role_value = normalize_access_role(getattr(user, "role", ""))
        action_value = "check_out" if getattr(log, "check_out_time", None) else "check_in"

        results.append(
            {
                "row": index,
                "user_id": getattr(user, "id", None),
                "name": build_access_display_name(user),
                "username": getattr(user, "username", "") or "--",
                "role": role_value,
                "role_label": _role_label_for_dashboard(role_value),
                "action": action_value,
                "status": getattr(log, "access_status", "") or "--",
                "check_in_time": check_in_display,
                "check_out_time": check_out_display,
                "hours": calculate_hours_text(log.check_in_time, log.check_out_time),
                "access_method": getattr(log, "access_method", "") or "--",
                "notes": getattr(log, "notes", "") or "--",
                "date": format_date_for_display(getattr(log, "access_date", None)),
            }
        )

    return results


def _role_label_for_dashboard(role_value):
    normalized_role = normalize_access_role(role_value)

    role_labels = {
        "estudiante": "Student",
        "student": "Student",
        "personal": "Staff",
        "staff": "Staff",
        "docente": "Professor",
        "professor": "Professor",
        "administrativo": "Admin",
        "admin": "Admin",
        "administrator": "Admin",
    }

    return role_labels.get(normalized_role, "User")


def get_global_access_stats():
    """
    Build global admin dashboard counters from users + access logs.
    """
    all_users = db.session.execute(db.select(User)).scalars().all()
    active_logs = get_all_active_access_logs()
    today_logs = get_today_access_logs()

    stats = {
        "total_users": 0,
        "students": 0,
        "staff": 0,
        "professors": 0,
        "admins": 0,
        "currently_inside": len(active_logs),
        "today_check_ins": 0,
        "today_check_outs": 0,
        "students_inside": 0,
        "staff_inside": 0,
        "professors_inside": 0,
        "admins_inside": 0,
    }

    for user in all_users:
        role = normalize_access_role(getattr(user, "role", ""))

        if not is_access_role_allowed(role):
            continue

        stats["total_users"] += 1

        if role in {"estudiante", "student"}:
            stats["students"] += 1
        elif role in {"personal", "staff"}:
            stats["staff"] += 1
        elif role in {"docente", "professor"}:
            stats["professors"] += 1
        elif role in {"administrativo", "admin", "administrator"}:
            stats["admins"] += 1

    for active_user in get_all_active_users():
        role = normalize_access_role(active_user.get("role"))

        if role in {"estudiante", "student"}:
            stats["students_inside"] += 1
        elif role in {"personal", "staff"}:
            stats["staff_inside"] += 1
        elif role in {"docente", "professor"}:
            stats["professors_inside"] += 1
        elif role in {"administrativo", "admin", "administrator"}:
            stats["admins_inside"] += 1

    for log in today_logs:
        if log.get("check_in_time") and log.get("check_in_time") != "--":
            stats["today_check_ins"] += 1
        if log.get("check_out_time") and log.get("check_out_time") != "--":
            stats["today_check_outs"] += 1

    return stats