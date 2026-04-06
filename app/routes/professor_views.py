from __future__ import annotations

import os
import socket
from uuid import uuid4
from datetime import datetime
from urllib.parse import urlencode

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
    jsonify,
    session,
)
from flask_login import current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app.database import db
from app.models.user_model import User

# 🔥 USE GLOBAL ACCESS SYSTEM (same as staff)
from app.services.access_log_service import (
    create_check_in,
    create_check_out,
    process_access_scan,
    get_user_current_access_status,
    build_access_table_rows,
)

# 🔥 USE SAME QR IMAGE + RESULT HTML SYSTEM
from app.routes.student_views import (
    generate_qr_image_data_uri,
    build_student_access_qr_id_code,
    process_access_scan_qr_text,
    _build_mobile_scan_result_html,
)


professor_views_bp = Blueprint(
    "professor_views",
    __name__,
    url_prefix="/professor",
)


ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
PROFESSOR_ROLE_VALUES = {"docente", "professor"}


def _professor_name() -> str:
    first_name = (getattr(current_user, "first_name", "") or "").strip()
    last_name = (getattr(current_user, "last_name", "") or "").strip()
    full_name = f"{first_name} {last_name}".strip()
    return full_name if full_name else (getattr(current_user, "username", "Professor") or "Professor")


def _is_allowed_image(filename: str) -> bool:
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_IMAGE_EXTENSIONS


def _is_professor_user() -> bool:
    role_value = (getattr(current_user, "role", "") or "").strip().lower()
    return role_value in PROFESSOR_ROLE_VALUES


def _sync_professor_language():
    session_language = (session.get("language") or "").strip().lower()

    if session_language not in {"en", "es"}:
        return

    current_language = (getattr(current_user, "language", "") or "").strip().lower()

    if current_language == session_language:
        return

    try:
        current_user.language = session_language
        db.session.commit()
    except Exception:
        db.session.rollback()


def _reject():
    return redirect(url_for("auth.login_page"))


def _redirect_success(msg):
    return redirect(url_for("professor_views.access_control_page", success=msg))


def _redirect_error(msg):
    return redirect(url_for("professor_views.access_control_page", error=msg))


def _clean_text(value):
    return str(value or "").strip()


def _clean_scan_code(value):
    return str(value or "").strip().rstrip("/")


def _score_ipv4_for_qr(ip_address: str) -> int:
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


def _build_professor_base_url():
    """
    Force a phone-usable LAN URL for professor QR.

    Important:
    We do NOT trust localhost / 127.0.0.1 / 0.0.0.0 here.
    """

    detected_lan_ip = _detect_best_lan_ip()

    configured_base_url = _clean_text(current_app.config.get("APP_BASE_URL", ""))
    if configured_base_url:
        lowered = configured_base_url.lower()
        if "127.0.0.1" not in lowered and "localhost" not in lowered and "0.0.0.0" not in lowered:
            return configured_base_url.rstrip("/")

    try:
        host = _clean_text(request.host)
        scheme = request.scheme or "http"

        port = "5000"
        if ":" in host:
            _, port = host.rsplit(":", 1)

        if detected_lan_ip:
            return f"{scheme}://{detected_lan_ip}:{port}".rstrip("/")
    except RuntimeError:
        pass

    if detected_lan_ip:
        return f"http://{detected_lan_ip}:5000"

    return ""


def build_professor_access_mobile_scan_url(user):
    base_url = _build_professor_base_url()
    user_id_code = _clean_scan_code(getattr(user, "user_id_code", ""))
    qr_id_code = _clean_scan_code(build_student_access_qr_id_code(user))

    query_params = {}
    if user_id_code:
        query_params["user_code"] = user_id_code
    else:
        query_params["qr_id_code"] = qr_id_code

    query_string = urlencode(query_params)

    if base_url:
        return f"{base_url}/professor/access-control/mobile-scan?{query_string}"

    return f"/professor/access-control/mobile-scan?{query_string}"


def build_professor_access_qr_payload(user):
    return build_professor_access_mobile_scan_url(user)


# =========================
# DASHBOARD
# =========================
@professor_views_bp.route("/dashboard")
@login_required
def dashboard():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    return render_template(
        "professor_dashboard.html",
        active_page="dashboard",
        professor_name=_professor_name(),
        role_label="Professor",
        account_role_label="Professor",
        account_type_label="Professor",
    )


# =========================
# ACCESS CONTROL (GLOBAL)
# =========================
@professor_views_bp.route("/access-control")
@login_required
def access_control_page():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    status = get_user_current_access_status(current_user.id)
    records = build_access_table_rows(current_user)

    access_qr_payload = build_professor_access_qr_payload(current_user)
    access_qr_image = generate_qr_image_data_uri(access_qr_payload)
    access_qr_id_code = build_student_access_qr_id_code(current_user)

    return render_template(
        "professor_access_control.html",
        active_page="access_control",
        professor_name=_professor_name(),
        role_label="Professor",
        account_role_label="Professor",
        account_type_label="Professor",
        selected_date=None,
        access_message=request.args.get("success"),
        access_error=request.args.get("error"),
        access_qr_image=access_qr_image,
        access_qr_payload=access_qr_payload,
        access_qr_id_code=access_qr_id_code,
        current_access_status=status,
        demo_records=records,
    )


# =========================
# CHECK IN
# =========================
@professor_views_bp.route("/access-control/check-in", methods=["POST"])
@login_required
def access_control_check_in():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    try:
        create_check_in(student_id=current_user.id)
        return _redirect_success("Checked in successfully")
    except Exception as e:
        return _redirect_error(str(e))


# =========================
# CHECK OUT
# =========================
@professor_views_bp.route("/access-control/check-out", methods=["POST"])
@login_required
def access_control_check_out():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    try:
        create_check_out(student_id=current_user.id)
        return _redirect_success("Checked out successfully")
    except Exception as e:
        return _redirect_error(str(e))


# =========================
# MOBILE SCAN (PUBLIC)
# =========================
@professor_views_bp.route("/access-control/mobile-scan", methods=["GET"])
def access_control_mobile_scan():
    qr_text = (
        _clean_scan_code(request.args.get("qr_text"))
        or _clean_scan_code(request.args.get("user_code"))
        or _clean_scan_code(request.args.get("qr_id_code"))
    )

    response_data, status_code = process_access_scan_qr_text(qr_text)
    return _build_mobile_scan_result_html(response_data, status_code), status_code


# =========================
# QR SCANNER (GLOBAL) ✅ FIXED
# =========================
@professor_views_bp.route("/access-control/scanner", methods=["GET", "POST"])
@login_required
def access_control_scanner():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    qr_text_value = ""
    scan_result = None

    if request.method == "POST":
        qr_text_value = (request.form.get("qr_text") or "").strip()

        # 🔥 FIX: use SAME global processor as student
        response_data, status_code = process_access_scan_qr_text(qr_text_value)

        scan_result = {
            "success": response_data.get("success", False),
            "message": response_data.get("message", ""),
            "action": response_data.get("action", ""),
            "professor_name": (
                response_data.get("professor_name")
                or response_data.get("user_name")
                or response_data.get("student_name")
                or "--"
            ),
            "username": response_data.get("username", ""),
            "status": response_data.get("status", ""),
            "check_in_time": response_data.get("check_in_time", ""),
            "check_out_time": response_data.get("check_out_time", ""),
            "status_code": status_code,
        }

    return render_template(
        "professor_qr_scanner.html",
        active_page="scanner",
        professor_name=_professor_name(),
        role_label="Professor",
        account_role_label="Professor",
        account_type_label="Professor",
        qr_text_value=qr_text_value,
        scan_result=scan_result,
    )


# =========================
# CONFIGURATION
# =========================
@professor_views_bp.route("/configuration")
@login_required
def configuration_page():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    return render_template(
        "professor_configuration.html",
        active_page="configuration",
        professor_name=_professor_name(),
        role_label="Professor",
        account_role_label="Professor",
        account_type_label="Professor",
        profile_message=request.args.get("success"),
        profile_error=request.args.get("error"),
    )


@professor_views_bp.route("/configuration/update", methods=["POST"])
@login_required
def configuration_update():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    first_name = (request.form.get("first_name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()

    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    try:
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.email = email
        current_user.phone = phone

        if any([current_password, new_password, confirm_password]):
            if not check_password_hash(current_user.password_hash, current_password):
                return _redirect_error("Current password incorrect")

            if new_password != confirm_password:
                return _redirect_error("Passwords do not match")

            current_user.password_hash = generate_password_hash(new_password)

        db.session.commit()
        return redirect(url_for("professor_views.configuration_page", success="Updated"))

    except Exception:
        db.session.rollback()
        return _redirect_error("Update failed")


@professor_views_bp.route("/configuration/update-photo", methods=["POST"])
@login_required
def configuration_update_photo():
    if not _is_professor_user():
        return _reject()

    _sync_professor_language()

    file = request.files.get("photo")

    if not file or not file.filename:
        return _redirect_error("No file selected")

    if not _is_allowed_image(file.filename):
        return _redirect_error("Invalid format")

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[1].lower()
    unique_name = f"professor_{current_user.id}_{uuid4().hex}.{ext}"

    folder = os.path.join(current_app.root_path, "static", "img", "profiles")
    os.makedirs(folder, exist_ok=True)

    path = os.path.join(folder, unique_name)
    file.save(path)

    try:
        current_user.photo_path = f"img/profiles/{unique_name}"
        db.session.commit()
        return redirect(url_for("professor_views.configuration_page", success="Photo updated"))
    except Exception:
        db.session.rollback()
        return _redirect_error("Photo update failed")