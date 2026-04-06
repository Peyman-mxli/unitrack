"""
student_views.py

Frontend browser routes for the UniTrack student panel.
Business logic must remain inside services.
"""

from datetime import datetime
from io import BytesIO
import base64
import hashlib
import os
import socket
from urllib.parse import urlencode, urlparse, parse_qs
from functools import wraps

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app.database import db
from app.models.user_model import User

try:
    from app.services.access_log_service import (
        build_student_access_table_rows,
        create_check_in,
        create_check_out,
        get_open_access_log_for_student,
        get_student_access_quick_stats,
        get_student_by_id,
        get_student_current_access_status,
    )
    ACCESS_LOG_SERVICE_AVAILABLE = True
except (ModuleNotFoundError, ImportError):
    ACCESS_LOG_SERVICE_AVAILABLE = False

    def build_student_access_table_rows(student):
        return []

    def create_check_in(student_id, access_method="qr", notes=""):
        raise ValueError("Access control service is not available.")

    def create_check_out(student_id, notes=""):
        raise ValueError("Access control service is not available.")

    def get_open_access_log_for_student(student_id):
        return None

    def get_student_access_quick_stats(student_id):
        return {
            "total_entries": 0,
            "total_exits": 0,
            "inside_count": 0,
            "outside_count": 0,
        }

    def get_student_by_id(student_id):
        return User.query.get(student_id)

    def get_student_current_access_status(student_id):
        return {
            "status": "unavailable",
            "label": "Access control unavailable",
            "is_inside": False,
        }

try:
    from app.services.attendance_service import (
        build_student_attendance_history_rows,
        get_student_attendance_class_options,
        get_student_attendance_summary,
    )
    ATTENDANCE_SERVICE_AVAILABLE = True
except (ModuleNotFoundError, ImportError):
    ATTENDANCE_SERVICE_AVAILABLE = False

    def build_student_attendance_history_rows(*args, **kwargs):
        return []

    def get_student_attendance_class_options(*args, **kwargs):
        return []

    def get_student_attendance_summary(*args, **kwargs):
        return {
            "attendance_percentage": 0,
            "attendance_percentage_color": "red",
            "present_count": 0,
            "late_count": 0,
            "absent_count": 0,
        }

try:
    from app.utils.role_required import role_required
except (ModuleNotFoundError, ImportError):
    def role_required(*allowed_roles):
        allowed_roles_normalized = {
            (role or "").strip().lower()
            for role in allowed_roles
            if (role or "").strip()
        }

        def decorator(view_function):
            @wraps(view_function)
            def wrapped(*args, **kwargs):
                user_role = (getattr(current_user, "role", "") or "").strip().lower()

                if user_role not in allowed_roles_normalized:
                    return redirect(url_for("auth.login_page"))

                return view_function(*args, **kwargs)
            return wrapped
        return decorator

try:
    from app.utils.security import hash_password, verify_password
except (ModuleNotFoundError, ImportError):
    from werkzeug.security import generate_password_hash, check_password_hash

    def hash_password(password):
        return generate_password_hash(password)

    def verify_password(password_hash, password):
        return check_password_hash(password_hash, password)


student_views_bp = Blueprint(
    "student_views",
    __name__,
    url_prefix="/student"
)


ALLOWED_PHOTO_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}


def _clean_text(value):
    return str(value or "").strip()


def _get_valid_language(value, default="en"):
    language = _clean_text(value).lower()

    if language in {"en", "es"}:
        return language

    return default


def _sync_student_language_from_session():
    """
    Keep the logged-in student language aligned with the selected session language.

    Why this fix exists:
    The global translator reads current_user.language first.
    If session is changed to Spanish but the database user still has English,
    student pages continue rendering in English.
    """

    session_language = _get_valid_language(session.get("language"), default="")

    if not session_language:
        return

    current_language = _get_valid_language(getattr(current_user, "language", ""), default="")

    if current_language == session_language:
        return

    try:
        current_user.language = session_language
        db.session.commit()
    except Exception:
        db.session.rollback()


def _clean_scan_code(value):
    """
    Normalize QR/User code values coming from URLs or scanners.

    Fix:
    Prevent accidental trailing slash values like:
    UT-UPBC-0001/
    """
    return str(value or "").strip().rstrip("/")


def _user_full_name(user):
    first_name = _clean_text(getattr(user, "first_name", ""))
    last_name = _clean_text(getattr(user, "last_name", ""))
    full_name = f"{first_name} {last_name}".strip()

    if full_name:
        return full_name

    return _clean_text(getattr(user, "username", "")) or "User"


def _student_full_name(student):
    return _user_full_name(student)


def _user_role_value(user):
    return (getattr(user, "role", "") or "").strip().lower()


def _user_role_label(user):
    role_value = _user_role_value(user)

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

    return role_labels.get(role_value, "User")


def _build_scan_subject_name(user):
    return _user_full_name(user)


def _build_scan_subject_key(user):
    role_value = _user_role_value(user)

    if role_value in {"personal", "staff"}:
        return "staff_name"

    if role_value in {"docente", "professor"}:
        return "professor_name"

    if role_value in {"administrativo", "admin", "administrator"}:
        return "admin_name"

    return "student_name"


def _build_access_route_prefix(user):
    """
    Build the correct route prefix for global access-control QR links.
    """

    role_value = _user_role_value(user)

    if role_value in {"administrativo", "admin", "administrator"}:
        return "admin"

    if role_value in {"personal", "staff"}:
        return "personal"

    if role_value in {"docente", "professor"}:
        return "professor"

    return "student"


def _configuration_form_data():
    return {
        "first_name": current_user.first_name or "",
        "last_name": current_user.last_name or "",
        "username": current_user.username or "",
        "email": current_user.email or "",
        "phone": getattr(current_user, "phone", "") or "",
        "language": _get_valid_language(getattr(current_user, "language", ""), default="en"),
    }


def _redirect_configuration_error(message):
    return redirect(url_for("student_views.configuration_page", error=message))


def _redirect_configuration_message(message):
    return redirect(url_for("student_views.configuration_page", message=message))


def _redirect_access_error(message):
    return redirect(url_for("student_views.access_control_page", error=message))


def _redirect_access_message(message):
    return redirect(url_for("student_views.access_control_page", message=message))


def _server_now():
    """
    Real current server datetime used for scanner result timestamps.
    """
    return datetime.now()


def _server_now_iso():
    return _server_now().replace(microsecond=0).isoformat()


def _build_mobile_scan_result_html(response_data, status_code):
    """
    Public HTML response for real phone scans.

    Why this fix exists:
    A phone camera scan should complete immediately even when the phone
    browser is not logged in. Redirecting to a protected page sends the
    user to login and makes the scan look broken.
    """

    success = bool(response_data.get("success"))
    title = "Access Registered" if success else "Scan Failed"
    message = _clean_text(response_data.get("message"))
    action = _clean_text(response_data.get("action")).replace("_", " ").title()
    subject_name = (
        _clean_text(response_data.get("student_name")) or
        _clean_text(response_data.get("user_name")) or
        _clean_text(response_data.get("staff_name")) or
        _clean_text(response_data.get("professor_name")) or
        _clean_text(response_data.get("admin_name")) or
        _clean_text(response_data.get("name"))
    )
    subject_role = _clean_text(response_data.get("role_label")) or "User"
    username = _clean_text(response_data.get("username"))
    user_id_code = _clean_text(response_data.get("user_id_code"))
    qr_id_code = _clean_text(response_data.get("qr_id_code"))
    status_label = _clean_text(response_data.get("status"))
    check_in_time = _clean_text(response_data.get("check_in_time"))
    check_out_time = _clean_text(response_data.get("check_out_time"))
    processed_at = _clean_text(response_data.get("processed_at")) or _server_now_iso()

    card_border = "#16a34a" if success else "#dc2626"
    badge_bg = "#dcfce7" if success else "#fee2e2"
    badge_text = "#166534" if success else "#991b1b"
    action_html = f"<p><strong>Action:</strong> {action}</p>" if action else ""
    subject_html = f"<p><strong>{subject_role}:</strong> {subject_name}</p>" if subject_name else ""
    username_html = f"<p><strong>Username:</strong> {username}</p>" if username else ""
    user_id_html = f"<p><strong>User ID:</strong> {user_id_code}</p>" if user_id_code else ""
    qr_id_html = f"<p><strong>QR ID:</strong> {qr_id_code}</p>" if qr_id_code else ""
    status_html = f"<p><strong>Status:</strong> {status_label}</p>" if status_label else ""
    check_in_html = f"<p><strong>Check-in time:</strong> {check_in_time}</p>" if check_in_time else ""
    check_out_html = f"<p><strong>Check-out time:</strong> {check_out_time}</p>" if check_out_time else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UniTrack Mobile Scan</title>
    <style>
        body {{
            margin: 0;
            padding: 24px;
            font-family: Arial, Helvetica, sans-serif;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            color: #0f172a;
        }}
        .wrap {{
            max-width: 560px;
            margin: 40px auto;
        }}
        .card {{
            background: #ffffff;
            border: 2px solid {card_border};
            border-radius: 18px;
            padding: 24px;
            box-shadow: 0 12px 32px rgba(15, 23, 42, 0.10);
        }}
        .badge {{
            display: inline-block;
            padding: 8px 14px;
            border-radius: 999px;
            background: {badge_bg};
            color: {badge_text};
            font-weight: 700;
            margin-bottom: 14px;
        }}
        h1 {{
            margin: 0 0 12px 0;
            font-size: 28px;
        }}
        p {{
            margin: 10px 0;
            line-height: 1.45;
        }}
        .message {{
            font-size: 16px;
            margin-bottom: 18px;
        }}
        .footer {{
            margin-top: 18px;
            font-size: 13px;
            color: #475569;
        }}
    </style>
</head>
<body>
    <div class="wrap">
        <div class="card">
            <div class="badge">{title}</div>
            <h1>UniTrack</h1>
            <p class="message">{message}</p>
            {action_html}
            {subject_html}
            {username_html}
            {user_id_html}
            {qr_id_html}
            {status_html}
            {check_in_html}
            {check_out_html}
            <div class="footer">
                <p><strong>Processed at:</strong> {processed_at}</p>
                <p><strong>HTTP status:</strong> {status_code}</p>
            </div>
        </div>
    </div>
</body>
</html>"""


def _extract_configuration_password_fields(form_data):
    """
    Read password fields from the configuration form safely.

    Why this fix exists:
    Some template versions may use slightly different input names.
    So I support the most common names without breaking older forms.
    """
    current_password = (
        _clean_text(form_data.get("current_password")) or
        _clean_text(form_data.get("old_password")) or
        _clean_text(form_data.get("actual_password"))
    )

    new_password = (
        _clean_text(form_data.get("new_password")) or
        _clean_text(form_data.get("password"))
    )

    confirm_password = (
        _clean_text(form_data.get("confirm_password")) or
        _clean_text(form_data.get("password_confirm")) or
        _clean_text(form_data.get("confirm_new_password"))
    )

    return current_password, new_password, confirm_password


def _extract_scan_text_from_json_payload(data):
    """
    Read scanner text from common JSON field names.

    Why this fix exists:
    Some frontend versions may send a different key than qr_text.
    If we only read one exact key, the scanner may look like it does nothing.
    """
    if not isinstance(data, dict):
        return ""

    candidate_keys = [
        "qr_text",
        "qr_payload",
        "qr_code",
        "scan_text",
        "payload",
        "manual_code",
        "user_code",
        "scan_url",
    ]

    for key in candidate_keys:
        value = str(data.get(key, "")).strip()
        if value:
            return value

    return ""


def _extract_scan_text_from_form(form_data):
    """
    Read scanner text from common form field names.

    Why this fix exists:
    Some browser templates may post a textarea/input using a different name.
    """
    candidate_keys = [
        "qr_text",
        "qr_payload",
        "qr_code",
        "scan_text",
        "payload",
        "manual_code",
        "user_code",
        "scan_url",
    ]

    for key in candidate_keys:
        value = str(form_data.get(key, "")).strip()
        if value:
            return value

    return ""


def _split_host_and_port(host_value):
    host_value = _clean_text(host_value)

    if not host_value:
        return "", ""

    if ":" in host_value:
        host_only, port = host_value.rsplit(":", 1)
        return host_only.strip(), port.strip()

    return host_value.strip(), ""


def _is_bad_qr_host(host_value):
    host_only, _ = _split_host_and_port(host_value)
    host_only = host_only.lower()

    return host_only in {"127.0.0.1", "localhost", "0.0.0.0"}


def _score_ipv4_for_qr(ip_address):
    ip_address = _clean_text(ip_address)

    if not ip_address:
        return -999

    if ip_address.startswith("127.") or ip_address == "0.0.0.0":
        return -999

    if ip_address.startswith("192.168."):
        return 300

    if ip_address.startswith("172."):
        try:
            second_octet = int(ip_address.split(".")[1])
            if 16 <= second_octet <= 31:
                return 250
        except Exception:
            pass

    if ip_address.startswith("10."):
        return 100

    return 50


def _detect_best_lan_ip():
    """
    Detect the best LAN IPv4 for QR URLs.
    Prefer 192.168.x.x over 172.16-31.x.x over 10.x.x.x.
    """
    candidates = []

    try:
        hostname, aliases, host_ips = socket.gethostbyname_ex(socket.gethostname())
        for ip in host_ips:
            ip = _clean_text(ip)
            if ip:
                candidates.append(ip)
    except Exception:
        pass

    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_socket.connect(("8.8.8.8", 80))
        detected_ip = _clean_text(test_socket.getsockname()[0])
        test_socket.close()
        if detected_ip:
            candidates.append(detected_ip)
    except Exception:
        pass

    try:
        addr_infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        for info in addr_infos:
            ip = _clean_text(info[4][0])
            if ip:
                candidates.append(ip)
    except Exception:
        pass

    unique_candidates = []
    seen = set()

    for ip in candidates:
        if ip not in seen:
            seen.add(ip)
            unique_candidates.append(ip)

    best_ip = ""
    best_score = -999

    for ip in unique_candidates:
        score = _score_ipv4_for_qr(ip)
        if score > best_score:
            best_score = score
            best_ip = ip

    return best_ip


def _sanitize_base_url_for_qr(base_url):
    """
    If config/request gives localhost or 127.0.0.1, replace it with current LAN IP.
    """
    base_url = _clean_text(base_url)
    if not base_url:
        return ""

    parsed = urlparse(base_url)

    scheme = parsed.scheme or "http"
    host_only = _clean_text(parsed.hostname)
    port = parsed.port

    if host_only and not _is_bad_qr_host(host_only):
        return base_url.rstrip("/")

    lan_ip = _detect_best_lan_ip()
    if not lan_ip:
        return base_url.rstrip("/")

    if port:
        return f"{scheme}://{lan_ip}:{port}"

    return f"{scheme}://{lan_ip}"


def _build_public_base_url():
    """
    Build a stable public base URL for QR links.

    Priority:
    1. APP_BASE_URL from config, but sanitize localhost values
    2. forwarded host/proto if present
    3. current request host, but sanitize localhost values
    4. fallback to detected LAN IP on port 5000
    """
    configured_base_url = _clean_text(current_app.config.get("APP_BASE_URL", ""))
    if configured_base_url:
        return _sanitize_base_url_for_qr(configured_base_url).rstrip("/")

    try:
        forwarded_proto = _clean_text(request.headers.get("X-Forwarded-Proto")) or request.scheme or "http"
        forwarded_host = _clean_text(request.headers.get("X-Forwarded-Host"))

        if forwarded_host:
            sanitized_forwarded = _sanitize_base_url_for_qr(f"{forwarded_proto}://{forwarded_host}")
            if sanitized_forwarded:
                return sanitized_forwarded.rstrip("/")

        request_scheme = request.scheme or "http"
        request_host = _clean_text(request.host)

        if request_host:
            sanitized_request = _sanitize_base_url_for_qr(f"{request_scheme}://{request_host}")
            if sanitized_request:
                return sanitized_request.rstrip("/")

    except RuntimeError:
        pass

    best_lan_ip = _detect_best_lan_ip()
    if best_lan_ip:
        return f"http://{best_lan_ip}:5000"

    return ""


def build_student_access_mobile_scan_url(student):
    """
    Build a real URL that phone cameras can open.

    Now:
    - role-aware (student/admin/staff/professor)
    - strips accidental trailing slash from codes
    - forces real LAN IP when localhost is detected
    """
    base_url = _build_public_base_url()

    user_id_code = _clean_scan_code(getattr(student, "user_id_code", ""))
    qr_id_code = _clean_scan_code(build_student_access_qr_id_code(student))
    route_prefix = _build_access_route_prefix(student)

    query_params = {}

    if user_id_code:
        query_params["user_code"] = user_id_code
    else:
        query_params["qr_id_code"] = qr_id_code

    route_path = f"/{route_prefix}/access-control/mobile-scan"

    if not base_url:
        return f"{route_path}?{urlencode(query_params)}"

    return f"{base_url}{route_path}?{urlencode(query_params)}"


def build_student_access_qr_payload(student):
    """
    Build the raw text payload encoded inside the QR image.

    Updated for real phone use:
    The QR now contains a scannable URL instead of plain text,
    so the phone camera can open the app directly.
    """
    return build_student_access_mobile_scan_url(student)


def build_student_access_qr_id_code(student):
    """
    Build a short manual fallback code for the student.
    """

    raw_text = f"{student.id}|{student.username}|{student.first_name}|{student.last_name}|{getattr(student, 'role', '')}"
    digest = hashlib.sha1(raw_text.encode("utf-8")).hexdigest().upper()

    first_two_digits = str(student.id).zfill(2)[-2:]

    letters_pool = "".join([char for char in digest if char.isalpha()])
    two_letters = letters_pool[:2] if len(letters_pool) >= 2 else "QR"

    last_two_digits = str((len(student.username) * 7 + student.id) % 100).zfill(2)

    return f"{first_two_digits}{two_letters}{last_two_digits}"


def get_user_by_id(user_id):
    """
    Generic user resolver for global QR access.
    """

    if not str(user_id).isdigit():
        return None

    user = None

    if ACCESS_LOG_SERVICE_AVAILABLE:
        try:
            user = get_student_by_id(int(user_id))
        except Exception:
            user = None

    if user:
        return user

    return User.query.get(int(user_id))


def find_user_by_access_qr_id_code(qr_id_code):
    """
    Resolve any UniTrack user from the short manual QR ID code.
    """

    qr_id_code = _clean_scan_code(qr_id_code).upper()

    if not qr_id_code:
        return None

    users = User.query.all()

    for user in users:
        try:
            if build_student_access_qr_id_code(user) == qr_id_code:
                return user
        except Exception:
            continue

    return None


def find_user_by_user_id_code(user_id_code):
    """
    Resolve any UniTrack user from the permanent UniTrack user ID code.
    """

    user_id_code = _clean_scan_code(user_id_code).upper()

    if not user_id_code:
        return None

    return User.query.filter(User.user_id_code == user_id_code).first()


def find_student_by_access_qr_id_code(qr_id_code):
    """
    Backward-compatible wrapper kept to avoid breaking other imports.
    """
    return find_user_by_access_qr_id_code(qr_id_code)


def find_student_by_user_id_code(user_id_code):
    """
    Backward-compatible wrapper kept to avoid breaking other imports.
    """
    return find_user_by_user_id_code(user_id_code)


def parse_student_access_qr_payload(qr_text):
    """
    Parse a UniTrack student access QR payload.

    Supported inputs:
    - legacy raw payload: UNITRACK|ACCESS|student_id=...|username=...|name=...
    - real phone URL QR: /student/access-control/mobile-scan?user_code=UT-UPBC-0001
    - real phone URL QR: /student/access-control/mobile-scan?qr_id_code=12AB34
    """

    if not qr_text:
        return None

    qr_text = qr_text.strip()

    if (
        qr_text.startswith("http://") or
        qr_text.startswith("https://") or
        qr_text.startswith("/student/") or
        qr_text.startswith("/admin/") or
        qr_text.startswith("/personal/") or
        qr_text.startswith("/professor/")
    ):
        parsed_url = urlparse(qr_text)
        query_values = parse_qs(parsed_url.query)

        user_code = _clean_scan_code(query_values.get("user_code", [""])[0])
        qr_id_code = _clean_scan_code(query_values.get("qr_id_code", [""])[0])
        qr_text_from_url = _clean_text(query_values.get("qr_text", [""])[0])

        if user_code:
            return {
                "type": "user_code",
                "user_code": user_code,
            }

        if qr_id_code:
            return {
                "type": "qr_id_code",
                "qr_id_code": qr_id_code,
            }

        if qr_text_from_url:
            return parse_student_access_qr_payload(qr_text_from_url)

        return None

    if not qr_text.startswith("UNITRACK|ACCESS|"):
        return None

    parts = qr_text.split("|")

    if len(parts) < 5:
        return None

    payload_data = {}

    for item in parts[2:]:
        if "=" not in item:
            continue

        key, value = item.split("=", 1)
        payload_data[key.strip()] = value.strip()

    student_id_text = payload_data.get("student_id", "").strip()
    username = payload_data.get("username", "").strip()
    name = payload_data.get("name", "").strip()

    if not student_id_text.isdigit():
        return None

    return {
        "type": "legacy_payload",
        "student_id": int(student_id_text),
        "username": username,
        "name": name,
    }


def generate_qr_image_data_uri(qr_text):
    """
    Generate a QR image in memory and return it as a data URI.
    """

    try:
        import qrcode
    except ImportError:
        return None

    try:
        qr = qrcode.QRCode(
            version=1,
            box_size=8,
            border=2
        )
        qr.add_data(qr_text)
        qr.make(fit=True)

        image = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        image.save(buffer, format="PNG")
        buffer.seek(0)

        encoded_image = base64.b64encode(buffer.read()).decode("utf-8")
        return f"data:image/png;base64,{encoded_image}"

    except Exception:
        return None


def _build_scan_success_response(user, action, log_object):
    response_data = {
        "success": True,
        "action": action,
        "message": "Check-in completed successfully." if action == "check_in" else "Check-out completed successfully.",
        "user_id": user.id,
        "user_name": _build_scan_subject_name(user),
        "student_name": _build_scan_subject_name(user),
        "username": getattr(user, "username", ""),
        "user_id_code": _clean_text(getattr(user, "user_id_code", "")),
        "qr_id_code": build_student_access_qr_id_code(user),
        "status": getattr(log_object, "access_status", ""),
        "check_in_time": (
            log_object.check_in_time.isoformat()
            if getattr(log_object, "check_in_time", None) else None
        ),
        "check_out_time": (
            log_object.check_out_time.isoformat()
            if getattr(log_object, "check_out_time", None) else None
        ),
        "processed_at": _server_now_iso(),
        "role": _user_role_value(user),
        "role_label": _user_role_label(user),
    }

    response_data[_build_scan_subject_key(user)] = _build_scan_subject_name(user)

    return response_data


def process_access_scan_qr_text(qr_text):
    """
    Central scan processor used by:
    - API scanner endpoint
    - browser scanner page
    - mobile phone GET scan endpoint
    """

    qr_text = str(qr_text or "").strip()

    if not qr_text:
        return {
            "success": False,
            "message": "QR text is required.",
            "processed_at": _server_now_iso(),
        }, 400

    user = None
    parsed_payload = parse_student_access_qr_payload(qr_text)

    if parsed_payload:
        if parsed_payload["type"] == "legacy_payload":
            student_id = parsed_payload["student_id"]
            qr_username = parsed_payload["username"]

            user = get_user_by_id(student_id)

            if not user:
                return {
                    "success": False,
                    "message": "User not found.",
                    "processed_at": _server_now_iso(),
                }, 404

            if _clean_text(getattr(user, "username", "")) != qr_username:
                return {
                    "success": False,
                    "message": "QR validation failed. User data mismatch.",
                    "processed_at": _server_now_iso(),
                }, 400

        elif parsed_payload["type"] == "user_code":
            user = find_user_by_user_id_code(parsed_payload["user_code"])

            if not user:
                return {
                    "success": False,
                    "message": "User not found for that User ID code.",
                    "processed_at": _server_now_iso(),
                }, 404

        elif parsed_payload["type"] == "qr_id_code":
            user = find_user_by_access_qr_id_code(parsed_payload["qr_id_code"])

            if not user:
                return {
                    "success": False,
                    "message": "User not found for that QR ID code.",
                    "processed_at": _server_now_iso(),
                }, 404

    else:
        user = find_user_by_user_id_code(qr_text)

        if not user:
            user = find_user_by_access_qr_id_code(qr_text)

        if not user:
            return {
                "success": False,
                "message": "Invalid UniTrack QR payload, User ID code, or QR ID code.",
                "processed_at": _server_now_iso(),
            }, 400

    if not ACCESS_LOG_SERVICE_AVAILABLE:
        return {
            "success": False,
            "message": "Access control service is not available.",
            "processed_at": _server_now_iso(),
        }, 400

    open_log = get_open_access_log_for_student(user.id)

    try:
        if open_log:
            updated_log = create_check_out(
                student_id=user.id,
                notes="QR scanner automatic check-out"
            )

            return _build_scan_success_response(
                user=user,
                action="check_out",
                log_object=updated_log
            ), 200

        new_log = create_check_in(
            student_id=user.id,
            access_method="qr",
            notes="QR scanner automatic check-in"
        )

        return _build_scan_success_response(
            user=user,
            action="check_in",
            log_object=new_log
        ), 200

    except ValueError as exc:
        return {
            "success": False,
            "message": str(exc),
            "processed_at": _server_now_iso(),
        }, 400

    except Exception:
        return {
            "success": False,
            "message": "Unexpected scanner error while processing the QR.",
            "processed_at": _server_now_iso(),
        }, 500


@student_views_bp.route("/dashboard")
@login_required
@role_required("estudiante")
def dashboard_page():
    _sync_student_language_from_session()
    student_name = _student_full_name(current_user)

    return render_template(
        "student_dashboard.html",
        student_name=student_name,
        active_page="dashboard"
    )


@student_views_bp.route("/access-control", methods=["GET"])
@login_required
@role_required("estudiante")
def access_control_page():
    """
    Student access control page.
    """

    _sync_student_language_from_session()
    student_name = _student_full_name(current_user)

    selected_date = request.args.get("date", "").strip()
    access_message = request.args.get("message", "").strip()
    access_error = request.args.get("error", "").strip()

    parsed_date = None

    if selected_date:
        try:
            parsed_date = datetime.strptime(selected_date, "%m/%d/%Y").date()
        except ValueError:
            parsed_date = None
            access_error = "Invalid date. Use MM/DD/YYYY format."

    all_records = build_student_access_table_rows(current_user)

    if parsed_date:
        filtered_records = [
            record for record in all_records
            if record.get("date") == selected_date
        ]
    else:
        filtered_records = all_records

    for index, record in enumerate(filtered_records, start=1):
        record["row"] = index

    quick_stats = get_student_access_quick_stats(current_user.id)
    current_access_status = get_student_current_access_status(current_user.id)

    access_qr_payload = build_student_access_qr_payload(current_user)
    access_qr_image = generate_qr_image_data_uri(access_qr_payload)
    access_qr_id_code = build_student_access_qr_id_code(current_user)

    return render_template(
        "student_access_control.html",
        student_name=student_name,
        active_page="access_control",
        demo_records=filtered_records,
        quick_stats=quick_stats,
        current_access_status=current_access_status,
        selected_date=selected_date,
        access_message=access_message,
        access_error=access_error,
        access_qr_payload=access_qr_payload,
        access_qr_image=access_qr_image,
        access_qr_id_code=access_qr_id_code,
        current_server_time=_server_now()
    )


@student_views_bp.route("/attendance-history", methods=["GET"])
@login_required
@role_required("estudiante")
def attendance_history_page():
    """
    Real student academic attendance history page.
    """

    _sync_student_language_from_session()
    student_name = _student_full_name(current_user)

    selected_date = request.args.get("date", "").strip()
    selected_class_name = request.args.get("class_name", "").strip()

    attendance_records = build_student_attendance_history_rows(
        student_id=current_user.id,
        selected_date=selected_date,
        selected_class_name=selected_class_name
    )

    class_options = get_student_attendance_class_options(
        student_id=current_user.id
    )

    summary = get_student_attendance_summary(
        student_id=current_user.id,
        selected_date=selected_date,
        selected_class_name=selected_class_name
    )

    return render_template(
        "student_attendance_history.html",
        student_name=student_name,
        active_page="attendance_history",
        attendance_records=attendance_records,
        class_options=class_options,
        selected_date=selected_date,
        selected_class_name=selected_class_name,
        attendance_percentage=summary["attendance_percentage"],
        attendance_percentage_color=summary["attendance_percentage_color"],
        present_count=summary["present_count"],
        late_count=summary["late_count"],
        absent_count=summary["absent_count"]
    )


@student_views_bp.route("/configuration", methods=["GET"])
@login_required
@role_required("estudiante")
def configuration_page():
    _sync_student_language_from_session()
    student_name = _student_full_name(current_user)

    profile_message = request.args.get("message", "").strip()
    profile_error = request.args.get("error", "").strip()

    last_password_change = getattr(current_user, "last_password_change", None)

    return render_template(
        "student_configuration.html",
        student_name=student_name,
        active_page="configuration",
        profile_message=profile_message,
        profile_error=profile_error,
        form_data=_configuration_form_data(),
        last_password_change=last_password_change
    )


@student_views_bp.route("/configuration/update", methods=["POST"])
@login_required
@role_required("estudiante")
def configuration_update():
    first_name = _clean_text(request.form.get("first_name"))
    last_name = _clean_text(request.form.get("last_name"))
    email = _clean_text(request.form.get("email")).lower()
    phone = _clean_text(request.form.get("phone"))
    language = _get_valid_language(request.form.get("language"), default=_get_valid_language(getattr(current_user, "language", ""), default="en"))
    submitted_username = _clean_text(request.form.get("username"))
    submitted_user_id = _clean_text(
        request.form.get("user_id") or request.form.get("id")
    )
    current_password, new_password, confirm_password = _extract_configuration_password_fields(request.form)

    if submitted_username and submitted_username != (current_user.username or ""):
        return _redirect_configuration_error(
            "Username cannot be changed after registration."
        )

    if submitted_user_id and submitted_user_id != str(current_user.id):
        return _redirect_configuration_error(
            "User ID cannot be changed after registration."
        )

    if not first_name:
        return _redirect_configuration_error("First name is required.")

    if not last_name:
        return _redirect_configuration_error("Last name is required.")

    if not email:
        return _redirect_configuration_error("Email is required.")

    if not phone:
        return _redirect_configuration_error("Phone is required.")

    existing_email_user = User.query.filter(
        User.email == email,
        User.id != current_user.id
    ).first()

    if existing_email_user:
        return _redirect_configuration_error(
            "This email is already in use."
        )

    password_change_requested = bool(current_password or new_password or confirm_password)

    if password_change_requested:
        if not current_password:
            return _redirect_configuration_error("Current password is required to change password.")

        if not verify_password(current_user.password_hash, current_password):
            return _redirect_configuration_error("Current password is incorrect.")

        if not new_password:
            return _redirect_configuration_error("New password is required.")

        if not confirm_password:
            return _redirect_configuration_error("Please confirm the new password.")

        if new_password != confirm_password:
            return _redirect_configuration_error("New password and confirmation do not match.")

        if new_password == current_password:
            return _redirect_configuration_error("New password must be different from current password.")

    try:
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.email = email
        current_user.phone = phone
        current_user.language = language
        session["language"] = language

        if password_change_requested:
            current_user.password_hash = hash_password(new_password)
            current_user.must_change_password = False

        db.session.commit()

        if password_change_requested:
            return _redirect_configuration_message(
                "Configuration and password updated successfully."
            )

        return _redirect_configuration_message(
            "Configuration updated successfully."
        )

    except Exception:
        db.session.rollback()
        return _redirect_configuration_error(
            "Failed to update configuration."
        )


@student_views_bp.route("/configuration/photo", methods=["POST"])
@login_required
@role_required("estudiante")
def configuration_update_photo():
    file = request.files.get("photo")

    if not file:
        return _redirect_configuration_error("No file selected.")

    safe_filename = secure_filename(file.filename or "")

    if not safe_filename:
        return _redirect_configuration_error("Invalid file.")

    if "." not in safe_filename:
        return _redirect_configuration_error("Invalid file.")

    extension = safe_filename.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_PHOTO_EXTENSIONS:
        return _redirect_configuration_error("File format not allowed.")

    upload_folder = os.path.join(
        current_app.root_path,
        "static",
        "uploads",
        "students"
    )
    os.makedirs(upload_folder, exist_ok=True)

    old_photo_path = _clean_text(getattr(current_user, "photo_path", ""))
    old_profile_image_path = _clean_text(getattr(current_user, "profile_image", ""))

    final_filename = f"student_{current_user.id}.{extension}"
    final_relative_path = f"uploads/students/{final_filename}"
    final_path = os.path.join(upload_folder, final_filename)

    try:
        for old_extension in ALLOWED_PHOTO_EXTENSIONS:
            old_filename = f"student_{current_user.id}.{old_extension}"
            old_file_path = os.path.join(upload_folder, old_filename)

            if os.path.exists(old_file_path) and old_file_path != final_path:
                try:
                    os.remove(old_file_path)
                except Exception:
                    pass

        file.save(final_path)

        if hasattr(current_user, "photo_path"):
            current_user.photo_path = final_relative_path

        if hasattr(current_user, "profile_image"):
            current_user.profile_image = final_relative_path

        if hasattr(current_user, "image"):
            current_user.image = final_relative_path

        db.session.commit()

        return _redirect_configuration_message("Photo updated successfully.")

    except Exception:
        db.session.rollback()

        if old_photo_path and hasattr(current_user, "photo_path"):
            current_user.photo_path = old_photo_path

        if old_profile_image_path and hasattr(current_user, "profile_image"):
            current_user.profile_image = old_profile_image_path

        return _redirect_configuration_error("Failed to upload photo.")


@student_views_bp.route("/access-control/check-in", methods=["POST"])
@login_required
@role_required("estudiante")
def access_control_check_in():
    """
    Create a new university access check-in for the logged-in student.
    """

    try:
        create_check_in(
            student_id=current_user.id,
            access_method="qr",
            notes="Student check-in from access control panel"
        )
        return _redirect_access_message("Check-in completed successfully.")

    except ValueError as exc:
        return _redirect_access_error(str(exc))

    except Exception:
        return _redirect_access_error("Failed to register check-in.")


@student_views_bp.route("/access-control/check-out", methods=["POST"])
@login_required
@role_required("estudiante")
def access_control_check_out():
    """
    Close the active university access log for the logged-in student.
    """

    try:
        create_check_out(
            student_id=current_user.id,
            notes="Student check-out from access control panel"
        )
        return _redirect_access_message("Check-out completed successfully.")

    except ValueError as exc:
        return _redirect_access_error(str(exc))

    except Exception:
        return _redirect_access_error("Failed to register check-out.")


@student_views_bp.route("/access-control/scan", methods=["POST"])
@login_required
@role_required("estudiante")
def access_control_scan():
    """
    Protected scanner endpoint for QR-based campus access.
    """

    data = request.get_json(silent=True) or {}
    qr_text = _extract_scan_text_from_json_payload(data)

    response_data, status_code = process_access_scan_qr_text(qr_text)
    return jsonify(response_data), status_code


@student_views_bp.route("/access-control/mobile-scan", methods=["GET"])
def access_control_mobile_scan():
    """
    Real phone camera scan endpoint.

    Public on purpose:
    a real phone camera must be able to open this route without being logged in.

    The QR opens this URL directly in the browser.
    Then the backend processes the student code and shows a direct result page.
    """

    qr_text = (
        _clean_scan_code(request.args.get("qr_text")) or
        _clean_scan_code(request.args.get("user_code")) or
        _clean_scan_code(request.args.get("qr_id_code"))
    )

    response_data, status_code = process_access_scan_qr_text(qr_text)
    return _build_mobile_scan_result_html(response_data, status_code), status_code


@student_views_bp.route("/access-control/scanner", methods=["GET", "POST"])
@login_required
@role_required("estudiante")
def access_control_scanner_page():
    """
    Simple browser-based QR scanner simulation page.
    """

    _sync_student_language_from_session()
    student_name = _student_full_name(current_user)
    scan_result = None
    qr_text_value = ""

    if request.method == "POST":
        qr_text_value = _extract_scan_text_from_form(request.form)

        if not qr_text_value:
            scan_result = {
                "success": False,
                "message": "QR text is required.",
                "action": "",
                "student_name": "",
                "user_name": "",
                "staff_name": "",
                "professor_name": "",
                "admin_name": "",
                "username": "",
                "user_id_code": "",
                "qr_id_code": "",
                "status": "",
                "check_in_time": "",
                "check_out_time": "",
                "processed_at": _server_now_iso(),
                "status_code": 400,
                "role_label": "",
            }
        else:
            response_data, status_code = process_access_scan_qr_text(qr_text_value)

            scan_result = {
                "success": response_data.get("success", False),
                "message": response_data.get("message", ""),
                "action": response_data.get("action", ""),
                "student_name": response_data.get("student_name", ""),
                "user_name": response_data.get("user_name", ""),
                "staff_name": response_data.get("staff_name", ""),
                "professor_name": response_data.get("professor_name", ""),
                "admin_name": response_data.get("admin_name", ""),
                "username": response_data.get("username", ""),
                "user_id_code": response_data.get("user_id_code", ""),
                "qr_id_code": response_data.get("qr_id_code", ""),
                "status": response_data.get("status", ""),
                "check_in_time": response_data.get("check_in_time", ""),
                "check_out_time": response_data.get("check_out_time", ""),
                "processed_at": response_data.get("processed_at", _server_now_iso()),
                "status_code": status_code,
                "role_label": response_data.get("role_label", ""),
            }

    return render_template(
        "student_qr_scanner.html",
        student_name=student_name,
        active_page="access_control",
        scan_result=scan_result,
        qr_text_value=qr_text_value
    )