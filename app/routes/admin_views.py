"""
admin_views.py

HTML views for the UniTrack admin panel.

Current scope:
- admin dashboard page
- validation code page
- validation code creation
- users management page
- user edit page
- user update action
- user role change page
- user role update action
- user password change page
- user password update action
- user ID change page
- user ID update action
- user delete page
- user delete action
- admin access control page
- admin access control check-in
- admin access control check-out
- admin QR scanner page
- placeholder pages for attendance history
- placeholder pages for configuration
"""

from datetime import datetime, date, timedelta
import os
import socket
from urllib.parse import urlencode

from flask import Blueprint, render_template, request, redirect, flash, url_for, current_app
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from app.database import db
from app.models.user_model import User
from app.models.validation_code_model import ValidationCode
from app.services.validation_code_service import create_validation_code
from app.services.access_log_service import (
    create_check_in,
    create_check_out,
    get_user_current_access_status,
    build_access_table_rows,
)
from app.routes.student_views import (
    generate_qr_image_data_uri,
    build_student_access_qr_id_code,
    process_access_scan_qr_text,
    _build_mobile_scan_result_html,
)


admin_views_bp = Blueprint("admin_views", __name__, url_prefix="/admin")

ALLOWED_ADMIN_PHOTO_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}


def safe_scalar(query, default=0):
    """
    Execute a scalar query safely.
    """
    try:
        result = db.session.execute(query).scalar()
        return result if result is not None else default
    except Exception:
        return default


def safe_all(query, default=None):
    """
    Execute a query safely and return all scalar results.
    """
    if default is None:
        default = []

    try:
        return db.session.execute(query).scalars().all()
    except Exception:
        return default


def safe_user_attribute(user, attribute_name, default_value=""):
    """
    Read user attributes safely because the project may still be evolving.
    """
    value = getattr(user, attribute_name, default_value)
    return value if value is not None else default_value


def normalize_role_for_ui(role_value):
    """
    Convert internal role names to UI-friendly English names.
    """
    role_map = {
        "estudiante": "Student",
        "administrativo": "Admin",
        "docente": "Professor",
        "personal": "Staff",
    }
    return role_map.get(str(role_value).strip().lower(), str(role_value).title())


def get_allowed_role_values():
    """
    Allowed role values for admin role management.
    """
    return {"estudiante", "administrativo", "docente", "personal"}


def is_user_online(user):
    """
    Basic online rule for admin panel.

    Current idea:
    - user is online if last_login_at exists and is within the last 15 minutes
    - if the field does not exist yet, fallback to False

    This keeps the system safe while the rest of the project is still evolving.
    """
    last_login_at = getattr(user, "last_login_at", None)
    if not last_login_at:
        return False

    try:
        return last_login_at >= datetime.utcnow() - timedelta(minutes=15)
    except Exception:
        return False


def get_user_by_id_for_admin(user_id):
    """
    Load one user safely for admin actions.
    """
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def set_user_password_safely(user, new_password):
    """
    Update a user password safely across possible model implementations.
    """
    if hasattr(user, "set_password") and callable(getattr(user, "set_password")):
        user.set_password(new_password)
        return

    if hasattr(user, "password_hash"):
        user.password_hash = generate_password_hash(new_password)
        return

    raise AttributeError("User model does not support password updates.")


def verify_user_password_safely(user, current_password):
    """
    Verify a user's current password safely across possible model implementations.
    """
    if hasattr(user, "check_password") and callable(getattr(user, "check_password")):
        try:
            return user.check_password(current_password)
        except Exception:
            return False

    stored_password_hash = getattr(user, "password_hash", None)
    if stored_password_hash:
        try:
            return check_password_hash(stored_password_hash, current_password)
        except Exception:
            return False

    return False


def normalize_user_id_code(user_id_code):
    """
    Normalize user ID code safely.
    """
    return str(user_id_code or "").strip().upper()


def is_valid_user_id_code_format(user_id_code):
    """
    Basic validation for admin manual user ID updates.

    Keeps validation simple and safe:
    - required
    - uppercase letters, numbers, and hyphens only
    """
    normalized = normalize_user_id_code(user_id_code)

    if not normalized:
        return False

    allowed_characters = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    return all(character in allowed_characters for character in normalized)


def get_user_by_user_id_code(user_id_code):
    """
    Find a user by user_id_code safely.
    """
    normalized = normalize_user_id_code(user_id_code)

    if not normalized or not hasattr(User, "user_id_code"):
        return None

    try:
        return db.session.execute(
            db.select(User).where(User.user_id_code == normalized)
        ).scalar_one_or_none()
    except Exception:
        return None


def count_admin_users():
    """
    Count current admin users safely.
    """
    try:
        return safe_scalar(
            db.select(db.func.count(User.id)).where(User.role == "administrativo"),
            default=0
        )
    except Exception:
        return 0


def is_default_admin_user(user):
    """
    Detect the protected default admin account safely.

    Current protection rule:
    - role is administrativo
    - username is Admin

    This matches the current UniTrack seed behavior.
    """
    role_value = str(safe_user_attribute(user, "role", "")).strip().lower()
    username_value = str(safe_user_attribute(user, "username", "")).strip().lower()

    return role_value == "administrativo" and username_value == "admin"


def can_delete_user(target_user, acting_user):
    """
    Central protection rules for deleting users.
    """
    if not target_user:
        return False, "User not found."

    if int(safe_user_attribute(target_user, "id", 0)) == int(safe_user_attribute(acting_user, "id", -1)):
        return False, "You cannot delete your own account while logged in."

    if is_default_admin_user(target_user):
        return False, "The default main admin account cannot be deleted."

    target_role = str(safe_user_attribute(target_user, "role", "")).strip().lower()

    if target_role == "administrativo" and count_admin_users() <= 1:
        return False, "You cannot delete the last remaining admin account."

    return True, ""


def _is_admin_user():
    role_value = str(safe_user_attribute(current_user, "role", "")).strip().lower()
    return role_value == "administrativo"


def _reject_non_admin():
    flash("Admin access only.", "error")
    return redirect("/auth/login-page")


def _admin_name():
    first_name = str(safe_user_attribute(current_user, "first_name", "")).strip()
    last_name = str(safe_user_attribute(current_user, "last_name", "")).strip()
    full_name = f"{first_name} {last_name}".strip()
    return full_name or str(safe_user_attribute(current_user, "username", "Admin")) or "Admin"


def _redirect_admin_access_success(message):
    return redirect(url_for("admin_views.admin_access_control", success=message))


def _redirect_admin_access_error(message):
    return redirect(url_for("admin_views.admin_access_control", error=message))


def _admin_configuration_redirect():
    return redirect(url_for("admin_views.admin_configuration"))


def _is_allowed_admin_photo(filename):
    filename = str(filename or "").strip()
    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_ADMIN_PHOTO_EXTENSIONS


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


def _build_admin_base_url():
    """
    Force a phone-usable LAN URL for admin QR.

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


def _save_admin_profile_photo(uploaded_file):
    """
    Save admin profile photo safely and update all possible image fields.
    """
    if not uploaded_file or not getattr(uploaded_file, "filename", ""):
        return

    safe_filename = secure_filename(uploaded_file.filename or "")
    if not safe_filename:
        raise ValueError("Invalid profile image file.")

    if not _is_allowed_admin_photo(safe_filename):
        raise ValueError("Profile image format not allowed. Use PNG, JPG, JPEG, or WEBP.")

    extension = safe_filename.rsplit(".", 1)[1].lower()

    upload_folder = os.path.join(
        current_app.root_path,
        "static",
        "uploads",
        "admins"
    )
    os.makedirs(upload_folder, exist_ok=True)

    final_filename = f"admin_{current_user.id}.{extension}"
    final_relative_path = f"uploads/admins/{final_filename}"
    final_full_path = os.path.join(upload_folder, final_filename)

    for old_extension in ALLOWED_ADMIN_PHOTO_EXTENSIONS:
        old_filename = f"admin_{current_user.id}.{old_extension}"
        old_file_path = os.path.join(upload_folder, old_filename)
        if os.path.exists(old_file_path) and old_file_path != final_full_path:
            try:
                os.remove(old_file_path)
            except Exception:
                pass

    uploaded_file.save(final_full_path)

    if hasattr(current_user, "profile_image"):
        current_user.profile_image = final_relative_path

    if hasattr(current_user, "photo_path"):
        current_user.photo_path = final_relative_path

    if hasattr(current_user, "image"):
        current_user.image = final_relative_path


def build_access_qr_payload_for_user(user):
    """
    Build admin QR payload using a real LAN/mobile-safe URL.
    """
    base_url = _build_admin_base_url()
    user_id_code = _clean_scan_code(getattr(user, "user_id_code", ""))
    qr_id_code = _clean_scan_code(build_student_access_qr_id_code(user))

    query_params = {}
    if user_id_code:
        query_params["user_code"] = user_id_code
    else:
        query_params["qr_id_code"] = qr_id_code

    query_string = urlencode(query_params)

    if base_url:
        return f"{base_url}/admin/access-control/mobile-scan?{query_string}"

    return f"/admin/access-control/mobile-scan?{query_string}"


def build_access_qr_id_code_for_user(user):
    """
    Use the same global backup access ID code builder already used by the rest of UniTrack.
    """
    return build_student_access_qr_id_code(user)


def process_global_access_scan_qr_text(qr_text_value):
    """
    Use the same global QR text processor already working for student, professor, and staff.
    """
    return process_access_scan_qr_text(qr_text_value)


def build_user_access_records(user, selected_date=""):
    """
    Build access records for the current user and optionally filter by date.

    This keeps admin access control aligned with the same history flow used
    by the other role dashboards.
    """
    records = build_access_table_rows(user) or []
    selected_date = str(selected_date or "").strip()

    if not selected_date:
        return records

    return [
        record for record in records
        if str(record.get("date", "")).strip() == selected_date
    ]


def perform_access_check_in_for_user(user, notes=""):
    """
    Register a check-in using the global access service.
    """
    return create_check_in(
        student_id=user.id,
        access_method="qr",
        notes=notes or "Access check-in from admin access control panel",
    )


def perform_access_check_out_for_user(user, notes=""):
    """
    Register a check-out using the global access service.
    """
    return create_check_out(
        student_id=user.id,
        notes=notes or "Access check-out from admin access control panel",
    )


def build_admin_dashboard_context():
    """
    Build dashboard context with safe fallback values.
    """

    total_validation_codes = safe_scalar(
        db.select(db.func.count(ValidationCode.id))
    )

    used_validation_codes = safe_scalar(
        db.select(db.func.count(ValidationCode.id)).where(ValidationCode.is_used.is_(True))
    )

    unused_validation_codes = safe_scalar(
        db.select(db.func.count(ValidationCode.id)).where(ValidationCode.is_used.is_(False))
    )

    total_students_signed_in = safe_scalar(
        db.select(db.func.count(User.id)).where(User.role == "estudiante")
    )

    recent_validation_codes = safe_all(
        db.select(ValidationCode)
        .order_by(ValidationCode.created_at.desc())
        .limit(10)
    )

    return {
        "now": datetime.utcnow(),
        "today": date.today(),

        # Validation codes
        "total_validation_codes": total_validation_codes,
        "used_validation_codes": used_validation_codes,
        "unused_validation_codes": unused_validation_codes,
        "recent_validation_codes": recent_validation_codes,

        # User totals
        "total_students_signed_in": total_students_signed_in,

        # Placeholder live totals for next steps
        "active_users_today": 0,
        "today_check_ins": 0,
        "today_check_outs": 0,

        "students_checked_in_today": 0,
        "students_checked_out_today": 0,
        "active_students_today": 0,

        "teachers_checked_in_today": 0,
        "teachers_checked_out_today": 0,
        "active_teachers_today": 0,

        "staff_checked_in_today": 0,
        "staff_checked_out_today": 0,
        "active_staff_today": 0,

        # Placeholder lists for future backend connection
        "recent_access_records": [],
        "live_presence_feed": [],
        "recent_admin_activity": [],
    }


def build_validation_codes_context():
    """
    Build context for validation codes page.
    """

    codes = safe_all(
        db.select(ValidationCode)
        .order_by(ValidationCode.created_at.desc())
        .limit(50)
    )

    return {
        "now": datetime.utcnow(),
        "codes": codes,
    }


def build_users_context():
    """
    Build context for admin users page.

    This is the first real backend connection for the Users section.
    It supports:
    - summary totals
    - online totals
    - search
    - role filter
    - status filter
    - user list for the table
    """

    search_text = str(request.args.get("search", "")).strip()
    selected_role = str(request.args.get("role", "")).strip().lower()
    selected_status = str(request.args.get("status", "")).strip().lower()

    users_query = db.select(User).order_by(User.id.desc())

    if search_text:
        like_value = f"%{search_text}%"
        users_query = users_query.where(
            db.or_(
                User.first_name.ilike(like_value),
                User.last_name.ilike(like_value),
                User.username.ilike(like_value),
                User.email.ilike(like_value),
                User.phone.ilike(like_value),
            )
        )

    if selected_role in get_allowed_role_values():
        users_query = users_query.where(User.role == selected_role)

    users = safe_all(users_query)

    user_rows = []
    total_online_now = 0
    total_students = 0
    total_admins = 0
    total_professors = 0
    total_staff = 0

    for user in users:
        internal_role = str(safe_user_attribute(user, "role", "")).strip().lower()
        is_online_now = is_user_online(user)

        if internal_role == "estudiante":
            total_students += 1
        elif internal_role == "administrativo":
            total_admins += 1
        elif internal_role == "docente":
            total_professors += 1
        elif internal_role == "personal":
            total_staff += 1

        if is_online_now:
            total_online_now += 1

        first_name = safe_user_attribute(user, "first_name", "")
        last_name = safe_user_attribute(user, "last_name", "")
        full_name = f"{first_name} {last_name}".strip()

        if not full_name:
            full_name = safe_user_attribute(user, "username", "Unknown User")

        is_active_user = getattr(user, "is_active_user", True)
        status_text = "Online" if is_online_now else ("Active" if is_active_user else "Inactive")

        user_rows.append(
            {
                "id": safe_user_attribute(user, "id", ""),
                "user_id_code": safe_user_attribute(user, "user_id_code", ""),
                "full_name": full_name,
                "username": safe_user_attribute(user, "username", ""),
                "email": safe_user_attribute(user, "email", ""),
                "phone": safe_user_attribute(user, "phone", ""),
                "role": internal_role,
                "role_label": normalize_role_for_ui(internal_role),
                "status": status_text,
                "is_online": is_online_now,
                "is_active_user": is_active_user,
                "must_change_password": getattr(user, "must_change_password", False),
                "last_login_at": getattr(user, "last_login_at", None),
                "can_delete": can_delete_user(user, current_user)[0],
                "is_default_admin_protected": is_default_admin_user(user),
            }
        )

    if selected_status == "online":
        user_rows = [row for row in user_rows if row["is_online"]]
    elif selected_status == "active":
        user_rows = [row for row in user_rows if row["is_active_user"]]
    elif selected_status == "inactive":
        user_rows = [row for row in user_rows if not row["is_active_user"]]

    return {
        "now": datetime.utcnow(),
        "page_title": "Users",

        # Filters
        "search_text": search_text,
        "selected_role": selected_role,
        "selected_status": selected_status,

        # Summary cards
        "total_students": total_students,
        "total_admins": total_admins,
        "total_professors": total_professors,
        "total_staff": total_staff,
        "total_online_now": total_online_now,

        # Table
        "users": user_rows,
        "total_users_found": len(user_rows),

        # Placeholder for next step
        "recent_admin_activity": [],
    }


@admin_views_bp.route("/dashboard", methods=["GET"])
@login_required
def admin_dashboard():
    """
    Main admin dashboard page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    context = build_admin_dashboard_context()
    return render_template("admin_dashboard.html", **context)


@admin_views_bp.route("/validation-codes", methods=["GET"])
@login_required
def admin_validation_codes():
    """
    Validation code management page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    context = build_validation_codes_context()
    return render_template("admin_validation_codes.html", **context)


@admin_views_bp.route("/validation-codes/create", methods=["POST"])
@login_required
def admin_create_validation_code():
    """
    Create a new validation code from admin panel.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    role = str(request.form.get("role", "")).strip().lower()
    hours_raw = str(request.form.get("hours", "24")).strip()

    allowed_roles = get_allowed_role_values()

    if role not in allowed_roles:
        flash("Invalid role selected.", "error")
        return redirect("/admin/validation-codes")

    try:
        expires_in_hours = int(hours_raw)
    except ValueError:
        flash("Invalid expiration time.", "error")
        return redirect("/admin/validation-codes")

    if expires_in_hours <= 0:
        flash("Expiration time must be greater than zero.", "error")
        return redirect("/admin/validation-codes")

    try:
        validation_code = create_validation_code(
            generated_by_user_id=current_user.id,
            role=role,
            expires_in_hours=expires_in_hours
        )

        flash(
            f"Validation code created successfully: {validation_code.code}",
            "success"
        )
    except ValueError as error:
        flash(str(error), "error")
    except Exception:
        db.session.rollback()
        flash("Unexpected error while creating validation code.", "error")

    return redirect("/admin/validation-codes")


@admin_views_bp.route("/users", methods=["GET"])
@login_required
def admin_users():
    """
    User monitoring page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    context = build_users_context()
    return render_template("admin_users.html", **context)


@admin_views_bp.route("/users/<int:user_id>/edit", methods=["GET"])
@login_required
def admin_edit_user(user_id):
    """
    Edit user page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    return render_template(
        "admin_user_edit.html",
        page_title="Edit User",
        user=user,
        role_label=normalize_role_for_ui(getattr(user, "role", "")),
        is_online=is_user_online(user),
        now=datetime.utcnow(),
    )


@admin_views_bp.route("/users/<int:user_id>/update", methods=["POST"])
@login_required
def admin_update_user(user_id):
    """
    Update editable user information.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    first_name = str(request.form.get("first_name", "")).strip()
    last_name = str(request.form.get("last_name", "")).strip()
    username = str(request.form.get("username", "")).strip()
    email = str(request.form.get("email", "")).strip()
    phone = str(request.form.get("phone", "")).strip()

    if not username:
        flash("Username is required.", "error")
        return redirect(f"/admin/users/{user_id}/edit")

    existing_username_user = db.session.execute(
        db.select(User).where(User.username == username, User.id != user.id)
    ).scalar_one_or_none()

    if existing_username_user:
        flash("That username is already in use.", "error")
        return redirect(f"/admin/users/{user_id}/edit")

    if email:
        existing_email_user = db.session.execute(
            db.select(User).where(User.email == email, User.id != user.id)
        ).scalar_one_or_none()

        if existing_email_user:
            flash("That email is already in use.", "error")
            return redirect(f"/admin/users/{user_id}/edit")

    try:
        if hasattr(user, "first_name"):
            user.first_name = first_name
        if hasattr(user, "last_name"):
            user.last_name = last_name
        if hasattr(user, "username"):
            user.username = username
        if hasattr(user, "email"):
            user.email = email
        if hasattr(user, "phone"):
            user.phone = phone

        db.session.commit()
        flash("User information updated successfully.", "success")
    except Exception:
        db.session.rollback()
        flash("Unexpected error while updating the user.", "error")

    return redirect(f"/admin/users/{user_id}/edit")


@admin_views_bp.route("/users/<int:user_id>/change-role", methods=["GET"])
@login_required
def admin_change_role_page(user_id):
    """
    Change role page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    return render_template(
        "admin_user_change_role.html",
        page_title="Change Role",
        user=user,
        current_role=safe_user_attribute(user, "role", "").strip().lower(),
        current_role_label=normalize_role_for_ui(getattr(user, "role", "")),
        allowed_roles=sorted(get_allowed_role_values()),
        is_online=is_user_online(user),
        now=datetime.utcnow(),
    )


@admin_views_bp.route("/users/<int:user_id>/change-role", methods=["POST"])
@login_required
def admin_change_role_action(user_id):
    """
    Update user role from admin panel.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    new_role = str(request.form.get("role", "")).strip().lower()
    allowed_roles = get_allowed_role_values()

    if new_role not in allowed_roles:
        flash("Invalid role selected.", "error")
        return redirect(f"/admin/users/{user_id}/change-role")

    if int(user.id) == int(current_user.id):
        flash("You cannot change your own role while logged in.", "error")
        return redirect(f"/admin/users/{user_id}/change-role")

    current_role = str(safe_user_attribute(user, "role", "")).strip().lower()

    if current_role == new_role:
        flash("This user already has that role.", "error")
        return redirect(f"/admin/users/{user_id}/change-role")

    try:
        if hasattr(user, "role"):
            user.role = new_role

        db.session.commit()
        flash("User role updated successfully.", "success")
    except Exception:
        db.session.rollback()
        flash("Unexpected error while updating the user role.", "error")

    return redirect(f"/admin/users/{user_id}/change-role")


@admin_views_bp.route("/users/<int:user_id>/change-password", methods=["GET"])
@login_required
def admin_change_password_page(user_id):
    """
    Change password page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    return render_template(
        "admin_user_change_password.html",
        page_title="Change Password",
        user=user,
        role_label=normalize_role_for_ui(getattr(user, "role", "")),
        is_online=is_user_online(user),
        now=datetime.utcnow(),
    )


@admin_views_bp.route("/users/<int:user_id>/change-password", methods=["POST"])
@login_required
def admin_change_password_action(user_id):
    """
    Update user password from admin panel.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    new_password = str(request.form.get("new_password", "")).strip()
    confirm_password = str(request.form.get("confirm_password", "")).strip()

    if not new_password:
        flash("New password is required.", "error")
        return redirect(f"/admin/users/{user_id}/change-password")

    if len(new_password) < 8:
        flash("Password must be at least 8 characters long.", "error")
        return redirect(f"/admin/users/{user_id}/change-password")

    if new_password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(f"/admin/users/{user_id}/change-password")

    try:
        set_user_password_safely(user, new_password)

        if hasattr(user, "must_change_password"):
            user.must_change_password = True

        db.session.commit()
        flash("User password updated successfully.", "success")
    except Exception:
        db.session.rollback()
        flash("Unexpected error while updating the user password.", "error")

    return redirect(f"/admin/users/{user_id}/change-password")


@admin_views_bp.route("/users/<int:user_id>/update-user-id", methods=["GET"])
@login_required
def admin_update_user_id_page(user_id):
    """
    Change user ID page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    return render_template(
        "admin_user_update_user_id.html",
        page_title="Update User ID",
        user=user,
        role_label=normalize_role_for_ui(getattr(user, "role", "")),
        is_online=is_user_online(user),
        current_user_id_code=safe_user_attribute(user, "user_id_code", ""),
        now=datetime.utcnow(),
    )


@admin_views_bp.route("/users/<int:user_id>/update-user-id", methods=["POST"])
@login_required
def admin_update_user_id_action(user_id):
    """
    Update user_id_code from admin panel.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    if not hasattr(user, "user_id_code"):
        flash("This user model does not support User ID updates.", "error")
        return redirect("/admin/users")

    new_user_id_code = normalize_user_id_code(request.form.get("user_id_code", ""))

    if not new_user_id_code:
        flash("User ID is required.", "error")
        return redirect(f"/admin/users/{user_id}/update-user-id")

    if not is_valid_user_id_code_format(new_user_id_code):
        flash("User ID can only contain letters, numbers, and hyphens.", "error")
        return redirect(f"/admin/users/{user_id}/update-user-id")

    existing_user = get_user_by_user_id_code(new_user_id_code)
    if existing_user and int(existing_user.id) != int(user.id):
        flash("That User ID is already in use.", "error")
        return redirect(f"/admin/users/{user_id}/update-user-id")

    current_user_id_code = normalize_user_id_code(safe_user_attribute(user, "user_id_code", ""))

    if current_user_id_code == new_user_id_code:
        flash("This user already has that User ID.", "error")
        return redirect(f"/admin/users/{user_id}/update-user-id")

    try:
        user.user_id_code = new_user_id_code
        db.session.commit()
        flash("User ID updated successfully.", "success")
    except Exception:
        db.session.rollback()
        flash("Unexpected error while updating the User ID.", "error")

    return redirect(f"/admin/users/{user_id}/update-user-id")


@admin_views_bp.route("/users/<int:user_id>/delete", methods=["GET"])
@login_required
def admin_delete_user_page(user_id):
    """
    Delete user confirmation page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    can_delete, protection_message = can_delete_user(user, current_user)

    return render_template(
        "admin_user_delete.html",
        page_title="Delete User",
        user=user,
        role_label=normalize_role_for_ui(getattr(user, "role", "")),
        is_online=is_user_online(user),
        can_delete=can_delete,
        protection_message=protection_message,
        now=datetime.utcnow(),
    )


@admin_views_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user_action(user_id):
    """
    Delete a user from admin panel with protection rules.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    user = get_user_by_id_for_admin(user_id)

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/users")

    confirmation_text = str(request.form.get("confirmation_text", "")).strip()
    expected_confirmation_text = "DELETE"

    if confirmation_text != expected_confirmation_text:
        flash("Type DELETE to confirm user deletion.", "error")
        return redirect(f"/admin/users/{user_id}/delete")

    can_delete, protection_message = can_delete_user(user, current_user)

    if not can_delete:
        flash(protection_message, "error")
        return redirect("/admin/users")

    try:
        deleted_user_name = (
            f"{safe_user_attribute(user, 'first_name', '')} "
            f"{safe_user_attribute(user, 'last_name', '')}"
        ).strip() or safe_user_attribute(user, "username", "Unknown User")

        db.session.delete(user)
        db.session.commit()
        flash(f"User deleted successfully: {deleted_user_name}", "success")
    except Exception:
        db.session.rollback()
        flash("Unexpected error while deleting the user.", "error")

    return redirect("/admin/users")


@admin_views_bp.route("/access-control", methods=["GET"])
@login_required
def admin_access_control():
    """
    Real admin access control page using the same global UniTrack access control
    flow already used by student, professor, and staff.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    selected_date = str(request.args.get("date", "")).strip()
    access_message = str(request.args.get("success", "")).strip()
    access_error = str(request.args.get("error", "")).strip()

    current_access_status = get_user_current_access_status(current_user.id)
    access_records = build_user_access_records(current_user, selected_date)

    access_qr_payload = build_access_qr_payload_for_user(current_user)
    access_qr_image = generate_qr_image_data_uri(access_qr_payload)
    access_qr_id_code = build_access_qr_id_code_for_user(current_user)

    return render_template(
        "admin_access_control.html",
        page_title="Access Control",
        active_page="access_control",
        admin_name=_admin_name(),
        selected_date=selected_date,
        access_message=access_message,
        access_error=access_error,
        access_qr_payload=access_qr_payload,
        access_qr_image=access_qr_image,
        access_qr_id_code=access_qr_id_code,
        current_access_status=current_access_status,
        access_records=access_records,
        demo_records=access_records,
        current_server_time=datetime.utcnow(),
    )


@admin_views_bp.route("/access-control/check-in", methods=["POST"])
@login_required
def admin_access_control_check_in():
    """
    Admin self check-in using the same global access service.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    try:
        perform_access_check_in_for_user(
            current_user,
            notes="Admin check-in from access control panel",
        )
        return _redirect_admin_access_success("Check-in completed successfully.")
    except ValueError as exc:
        return _redirect_admin_access_error(str(exc))
    except Exception:
        return _redirect_admin_access_error("Failed to register check-in.")


@admin_views_bp.route("/access-control/check-out", methods=["POST"])
@login_required
def admin_access_control_check_out():
    """
    Admin self check-out using the same global access service.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    try:
        perform_access_check_out_for_user(
            current_user,
            notes="Admin check-out from access control panel",
        )
        return _redirect_admin_access_success("Check-out completed successfully.")
    except ValueError as exc:
        return _redirect_admin_access_error(str(exc))
    except Exception:
        return _redirect_admin_access_error("Failed to register check-out.")


@admin_views_bp.route("/access-control/scanner", methods=["GET", "POST"])
@login_required
def admin_access_control_scanner():
    """
    Admin browser QR scanner using the same global processor already working
    for student, professor, and staff.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    qr_text_value = ""
    scan_result = None

    if request.method == "POST":
        qr_text_value = str(request.form.get("qr_text", "")).strip()

        response_data, status_code = process_global_access_scan_qr_text(qr_text_value)

        scan_result = {
            "success": response_data.get("success", False),
            "message": response_data.get("message", ""),
            "action": response_data.get("action", ""),
            "admin_name": (
                response_data.get("admin_name")
                or response_data.get("user_name")
                or response_data.get("student_name")
                or "--"
            ),
            "user_name": (
                response_data.get("user_name")
                or response_data.get("student_name")
                or response_data.get("admin_name")
                or "--"
            ),
            "username": response_data.get("username", ""),
            "status": response_data.get("status", ""),
            "check_in_time": response_data.get("check_in_time", ""),
            "check_out_time": response_data.get("check_out_time", ""),
            "status_code": status_code,
        }

    return render_template(
        "admin_qr_scanner.html",
        page_title="QR Scanner",
        active_page="access_control",
        admin_name=_admin_name(),
        qr_text_value=qr_text_value,
        scan_result=scan_result,
    )


@admin_views_bp.route("/access-control/mobile-scan", methods=["GET"])
def admin_access_control_mobile_scan():
    """
    Public admin mobile scan endpoint.

    This must stay public so a real phone camera can open the admin QR URL
    without requiring a logged-in browser session first.
    """

    qr_text_value = (
        _clean_scan_code(request.args.get("qr_text"))
        or _clean_scan_code(request.args.get("user_code"))
        or _clean_scan_code(request.args.get("qr_id_code"))
    )

    response_data, status_code = process_global_access_scan_qr_text(qr_text_value)
    return _build_mobile_scan_result_html(response_data, status_code), status_code


@admin_views_bp.route("/attendance-history", methods=["GET"])
@login_required
def admin_attendance_history():
    """
    Attendance history page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    return render_template(
        "admin_base.html",
        page_title="Attendance History"
    )


@admin_views_bp.route("/configuration", methods=["GET", "POST"])
@login_required
def admin_configuration():
    """
    Admin configuration page.
    """
    if not _is_admin_user():
        return _reject_non_admin()

    if request.method == "POST":
        first_name = str(request.form.get("first_name", "")).strip()
        last_name = str(request.form.get("last_name", "")).strip()
        email = str(request.form.get("email", "")).strip().lower()
        phone = str(request.form.get("phone", "")).strip()
        language = str(request.form.get("language", "en")).strip().lower()

        current_password = str(request.form.get("current_password", "")).strip()
        new_password = str(request.form.get("new_password", "")).strip()
        confirm_password = str(request.form.get("confirm_password", "")).strip()

        uploaded_profile_image = request.files.get("profile_image")

        if not first_name:
            flash("First name is required.", "error")
            return _admin_configuration_redirect()

        if not last_name:
            flash("Last name is required.", "error")
            return _admin_configuration_redirect()

        if not email:
            flash("Email is required.", "error")
            return _admin_configuration_redirect()

        if not phone:
            flash("Phone number is required.", "error")
            return _admin_configuration_redirect()

        if language not in {"en", "es"}:
            language = "en"

        existing_email_user = db.session.execute(
            db.select(User).where(User.email == email, User.id != current_user.id)
        ).scalar_one_or_none()

        if existing_email_user:
            flash("That email is already in use.", "error")
            return _admin_configuration_redirect()

        password_change_requested = bool(current_password or new_password or confirm_password)

        if password_change_requested:
            if not current_password:
                flash("Current password is required to change password.", "error")
                return _admin_configuration_redirect()

            if not verify_user_password_safely(current_user, current_password):
                flash("Current password is incorrect.", "error")
                return _admin_configuration_redirect()

            if not new_password:
                flash("New password is required.", "error")
                return _admin_configuration_redirect()

            if len(new_password) < 8:
                flash("New password must be at least 8 characters long.", "error")
                return _admin_configuration_redirect()

            if not confirm_password:
                flash("Please confirm the new password.", "error")
                return _admin_configuration_redirect()

            if new_password != confirm_password:
                flash("New password and confirmation do not match.", "error")
                return _admin_configuration_redirect()

            if new_password == current_password:
                flash("New password must be different from current password.", "error")
                return _admin_configuration_redirect()

        try:
            if hasattr(current_user, "first_name"):
                current_user.first_name = first_name

            if hasattr(current_user, "last_name"):
                current_user.last_name = last_name

            if hasattr(current_user, "email"):
                current_user.email = email

            if hasattr(current_user, "phone"):
                current_user.phone = phone

            if hasattr(current_user, "language"):
                current_user.language = language

            if uploaded_profile_image and str(uploaded_profile_image.filename or "").strip():
                _save_admin_profile_photo(uploaded_profile_image)

            if password_change_requested:
                set_user_password_safely(current_user, new_password)
                if hasattr(current_user, "must_change_password"):
                    current_user.must_change_password = False

            db.session.commit()

            if password_change_requested:
                flash("Admin configuration and password updated successfully.", "success")
            else:
                flash("Admin configuration updated successfully.", "success")

            return _admin_configuration_redirect()

        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return _admin_configuration_redirect()
        except Exception:
            db.session.rollback()
            flash("Failed to update admin configuration.", "error")
            return _admin_configuration_redirect()

    return render_template(
        "admin_configuration.html",
        page_title="Configuration"
    )