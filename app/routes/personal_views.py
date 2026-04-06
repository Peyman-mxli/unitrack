from __future__ import annotations

import os
import socket
from uuid import uuid4
from urllib.parse import urlencode

from flask import Blueprint, render_template, redirect, url_for, request, current_app, session
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app.database import db

# 🔥 IMPORT GLOBAL ACCESS SYSTEM
from app.services.access_log_service import (
    create_check_in,
    create_check_out,
    process_access_scan,
    get_user_current_access_status,
    build_access_table_rows,
)

# 🔥 IMPORT QR IMAGE + MOBILE RESULT HTML
from app.routes.student_views import (
    generate_qr_image_data_uri,
    build_student_access_qr_id_code,
    _build_mobile_scan_result_html,
    process_access_scan_qr_text,
)


personal_views_bp = Blueprint(
    "personal_views",
    __name__,
    url_prefix="/personal",
)


# 🔥 STRICT ROLE CONTROL
PERSONAL_ROLE_VALUES = {"personal"}
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def _is_personal_user():
    role_value = (getattr(current_user, "role", "") or "").strip().lower()
    return role_value in PERSONAL_ROLE_VALUES


def _reject():
    return redirect(url_for("auth.login_page"))


def _current_language():
    session_language = (session.get("language") or "").strip().lower()
    user_language = (getattr(current_user, "language", "") or "").strip().lower()

    if session_language in {"es", "en"}:
        return session_language

    if user_language in {"es", "en"}:
        return user_language

    return "en"


def _sync_personal_language():
    """
    Keep staff pages using the language selected on login page.
    Session language wins and is copied into current_user.language.
    """
    try:
        if not getattr(current_user, "is_authenticated", False):
            return

        selected_language = _current_language()
        current_language = (getattr(current_user, "language", "") or "").strip().lower()

        if selected_language in {"es", "en"}:
            session["language"] = selected_language

        if selected_language in {"es", "en"} and current_language != selected_language:
            current_user.language = selected_language
            db.session.commit()

    except Exception:
        db.session.rollback()


def _staff_name():
    first = (getattr(current_user, "first_name", "") or "").strip()
    last = (getattr(current_user, "last_name", "") or "").strip()
    full = f"{first} {last}".strip()

    language = _current_language()
    fallback_name = "Personal" if language == "es" else "Staff"

    return full if full else (getattr(current_user, "username", fallback_name) or fallback_name)


def _is_allowed_image(filename: str) -> bool:
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_IMAGE_EXTENSIONS


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


def _build_personal_base_url():
    """
    Force a phone-usable LAN URL for staff QR.

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


def build_personal_access_mobile_scan_url(user):
    base_url = _build_personal_base_url()
    user_id_code = _clean_scan_code(getattr(user, "user_id_code", ""))
    qr_id_code = _clean_scan_code(build_student_access_qr_id_code(user))

    query_params = {}
    if user_id_code:
        query_params["user_code"] = user_id_code
    else:
        query_params["qr_id_code"] = qr_id_code

    query_string = urlencode(query_params)

    if base_url:
        return f"{base_url}/personal/access-control/mobile-scan?{query_string}"

    return f"/personal/access-control/mobile-scan?{query_string}"


def build_personal_access_qr_payload(user):
    return build_personal_access_mobile_scan_url(user)


# =========================
# DASHBOARD
# =========================
@personal_views_bp.route("/dashboard")
@login_required
def dashboard():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()
    role_label = "Personal" if language == "es" else "Staff"

    return render_template(
        "personal_dashboard.html",
        active_page="dashboard",
        staff_name=_staff_name(),
        role_label=role_label,
        account_role_label=role_label,
        account_type_label=role_label,
    )


# =========================
# ACCESS CONTROL (REAL)
# =========================
@personal_views_bp.route("/access-control")
@login_required
def access_control_page():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()
    role_label = "Personal" if language == "es" else "Staff"

    status = get_user_current_access_status(current_user.id)
    records = build_access_table_rows(current_user)

    access_qr_payload = build_personal_access_qr_payload(current_user)
    access_qr_image = generate_qr_image_data_uri(access_qr_payload)
    access_qr_id_code = build_student_access_qr_id_code(current_user)

    return render_template(
        "personal_access_control.html",
        active_page="access_control",
        staff_name=_staff_name(),
        role_label=role_label,
        account_role_label=role_label,
        account_type_label=role_label,
        current_access_status=status,
        access_qr_image=access_qr_image,
        access_qr_payload=access_qr_payload,
        access_qr_id_code=access_qr_id_code,
        demo_records=records,
        selected_date=None,
        access_message=request.args.get("success"),
        access_error=request.args.get("error"),
    )


# =========================
# CHECK IN (REAL)
# =========================
@personal_views_bp.route("/access-control/check-in", methods=["POST"])
@login_required
def access_control_check_in():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()

    try:
        create_check_in(personal_id=current_user.id)
        success_message = "Entrada registrada correctamente" if language == "es" else "Checked in successfully"
        return redirect(url_for("personal_views.access_control_page", success=success_message))
    except Exception as e:
        return redirect(url_for("personal_views.access_control_page", error=str(e)))


# =========================
# CHECK OUT (REAL)
# =========================
@personal_views_bp.route("/access-control/check-out", methods=["POST"])
@login_required
def access_control_check_out():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()

    try:
        create_check_out(personal_id=current_user.id)
        success_message = "Salida registrada correctamente" if language == "es" else "Checked out successfully"
        return redirect(url_for("personal_views.access_control_page", success=success_message))
    except Exception as e:
        return redirect(url_for("personal_views.access_control_page", error=str(e)))


# =========================
# MOBILE SCAN (PUBLIC)
# =========================
@personal_views_bp.route("/access-control/mobile-scan", methods=["GET"])
def access_control_mobile_scan():
    qr_text = (
        _clean_scan_code(request.args.get("qr_text"))
        or _clean_scan_code(request.args.get("user_code"))
        or _clean_scan_code(request.args.get("qr_id_code"))
    )

    response_data, status_code = process_access_scan_qr_text(qr_text)
    return _build_mobile_scan_result_html(response_data, status_code), status_code


# =========================
# QR SCANNER (REAL GLOBAL)
# =========================
@personal_views_bp.route("/access-control/scanner", methods=["GET", "POST"])
@login_required
def access_control_scanner():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()
    role_label = "Personal" if language == "es" else "Staff"

    qr_text_value = ""
    scan_result = None

    if request.method == "POST":
        qr_text_value = (request.form.get("qr_text") or "").strip()

        response_data, status_code = process_access_scan_qr_text(qr_text_value)

        scan_result = {
            "success": response_data.get("success", False),
            "message": response_data.get("message", ""),
            "action": response_data.get("action", ""),
            "staff_name": (
                response_data.get("staff_name")
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
        "personal_qr_scanner.html",
        active_page="scanner",
        staff_name=_staff_name(),
        role_label=role_label,
        account_role_label=role_label,
        account_type_label=role_label,
        qr_text_value=qr_text_value,
        scan_result=scan_result,
    )


# =========================
# CONFIGURATION
# =========================
@personal_views_bp.route("/configuration")
@login_required
def configuration_page():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()
    role_label = "Personal" if language == "es" else "Staff"

    return render_template(
        "personal_configuration.html",
        active_page="configuration",
        staff_name=_staff_name(),
        role_label=role_label,
        account_role_label=role_label,
        account_type_label=role_label,
        profile_message=request.args.get("success"),
        profile_error=request.args.get("error"),
    )


@personal_views_bp.route("/configuration/update", methods=["POST"])
@login_required
def configuration_update():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()

    first_name = (request.form.get("first_name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    selected_language = (request.form.get("language") or session.get("language") or getattr(current_user, "language", "") or language).strip().lower()

    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    try:
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.email = email
        current_user.phone = phone

        if selected_language in {"es", "en"}:
            current_user.language = selected_language
            session["language"] = selected_language
            language = selected_language

        wants_password_change = any([current_password, new_password, confirm_password])

        if wants_password_change:
            if not current_password:
                error_message = (
                    "La contraseña actual es obligatoria para cambiar tu contraseña."
                    if language == "es"
                    else "Current password is required to change your password."
                )
                return redirect(
                    url_for(
                        "personal_views.configuration_page",
                        error=error_message,
                    )
                )

            password_hash = getattr(current_user, "password_hash", "") or ""
            if not password_hash or not check_password_hash(password_hash, current_password):
                error_message = (
                    "La contraseña actual es incorrecta."
                    if language == "es"
                    else "Current password is incorrect."
                )
                return redirect(
                    url_for(
                        "personal_views.configuration_page",
                        error=error_message,
                    )
                )

            if not new_password:
                error_message = (
                    "La nueva contraseña es obligatoria."
                    if language == "es"
                    else "New password is required."
                )
                return redirect(
                    url_for(
                        "personal_views.configuration_page",
                        error=error_message,
                    )
                )

            if new_password != confirm_password:
                error_message = (
                    "La nueva contraseña y la confirmación no coinciden."
                    if language == "es"
                    else "New password and confirm password do not match."
                )
                return redirect(
                    url_for(
                        "personal_views.configuration_page",
                        error=error_message,
                    )
                )

            current_user.password_hash = generate_password_hash(new_password)

        db.session.commit()

        success_message = (
            "Configuración actualizada correctamente."
            if language == "es"
            else "Configuration updated successfully."
        )

        return redirect(
            url_for(
                "personal_views.configuration_page",
                success=success_message,
            )
        )

    except Exception:
        db.session.rollback()
        error_message = (
            "No se puede actualizar la configuración en este momento."
            if language == "es"
            else "Unable to update configuration right now."
        )
        return redirect(
            url_for(
                "personal_views.configuration_page",
                error=error_message,
            )
        )


@personal_views_bp.route("/configuration/update-photo", methods=["POST"])
@login_required
def configuration_update_photo():
    if not _is_personal_user():
        return _reject()

    _sync_personal_language()
    language = _current_language()

    file = request.files.get("photo")

    if not file or not file.filename:
        error_message = (
            "Por favor selecciona primero un archivo de imagen."
            if language == "es"
            else "Please select an image file first."
        )
        return redirect(
            url_for(
                "personal_views.configuration_page",
                error=error_message,
            )
        )

    if not _is_allowed_image(file.filename):
        error_message = (
            "Formato de imagen no válido. Usa PNG, JPG, JPEG, GIF o WEBP."
            if language == "es"
            else "Invalid image format. Use PNG, JPG, JPEG, GIF, or WEBP."
        )
        return redirect(
            url_for(
                "personal_views.configuration_page",
                error=error_message,
            )
        )

    filename = secure_filename(file.filename)
    extension = filename.rsplit(".", 1)[1].lower()
    unique_filename = f"staff_{getattr(current_user, 'id', 'user')}_{uuid4().hex}.{extension}"

    upload_folder = os.path.join(current_app.root_path, "static", "img", "profiles")
    os.makedirs(upload_folder, exist_ok=True)

    save_path = os.path.join(upload_folder, unique_filename)
    file.save(save_path)

    try:
        current_user.photo_path = f"img/profiles/{unique_filename}"
        db.session.commit()

        success_message = (
            "Foto de perfil actualizada correctamente."
            if language == "es"
            else "Profile photo updated successfully."
        )

        return redirect(
            url_for(
                "personal_views.configuration_page",
                success=success_message,
            )
        )

    except Exception:
        db.session.rollback()
        error_message = (
            "No se puede actualizar la foto de perfil en este momento."
            if language == "es"
            else "Unable to update profile photo right now."
        )
        return redirect(
            url_for(
                "personal_views.configuration_page",
                error=error_message,
            )
        )