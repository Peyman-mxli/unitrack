"""
auth_routes.py

Professional authentication routes for UniTrack.

This file now supports:
- register API
- browser register page
- API login
- browser login page
- forgot password browser flow
- secure reset-password token flow
- logout
- current user info
- forced password change flow

Security rules:
- validation code is required for all registration roles
- forgot password requires BOTH email and phone number
- reset password link uses signed expiring token
"""

from flask import Blueprint, request, jsonify, render_template, redirect, current_app, session, url_for
from flask_login import login_user, logout_user, current_user, login_required
from sqlalchemy import func
from werkzeug.utils import secure_filename
import os
import uuid

from app.database import db
from app.models.user_model import User
from app.services.user_service import (
    create_user,
    get_user_by_username,
    get_user_by_email,
    update_last_login
)
from app.services.validation_code_service import (
    validate_code_for_use,
    mark_validation_code_as_used
)
from app.services.email_service import send_password_reset_email
from app.services.password_reset_service import (
    verify_password_reset_token,
    generate_password_reset_token
)
from app.utils.security import hash_password, verify_password

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def authenticate_user(login_value, password):
    """
    Authenticate user by email or username.

    Teaching idea:
    Users can log in with either:
    - email
    - username

    Professional improvement:
    I first try the service function,
    then I add a case-insensitive email fallback directly with SQLAlchemy.
    This helps prevent email matching bugs caused by letter case.
    """

    login_value = str(login_value or "").strip()
    password = str(password or "").strip()

    if not login_value or not password:
        return None, "login and password are required"

    user = get_user_by_email(login_value.lower())

    if not user:
        user = User.query.filter(
            func.lower(User.email) == login_value.lower()
        ).first()

    if not user:
        user = get_user_by_username(login_value)

    if not user:
        return None, "User not found"

    if not user.is_active_user:
        return None, "User account is inactive"

    if not verify_password(user.password_hash, password):
        return None, "Invalid password"

    return user, None


def normalize_role(role_value):
    """
    Normalize role text from browser/API forms.

    Compatibility rules:
    - old value 'trabajador' is converted to 'personal'
    - English role values are converted to UniTrack internal role names
    """

    role_value = str(role_value or "estudiante").strip().lower()

    role_aliases = {
        "trabajador": "personal",
        "student": "estudiante",
        "teacher": "docente",
        "professor": "docente",
        "staff": "personal",
        "admin": "administrativo",
        "administrator": "administrativo"
    }

    return role_aliases.get(role_value, role_value)


def normalize_phone(phone_value):
    """
    Normalize phone text for comparison.

    This removes non-digit characters so:
    - 6861234567
    - 686-123-4567
    - (686) 123 4567

    can still match the same stored number.
    """

    phone_value = str(phone_value or "").strip()

    cleaned = []
    for character in phone_value:
        if character.isdigit():
            cleaned.append(character)

    return "".join(cleaned)


def get_phone_variants(phone_value):
    """
    Build phone variants for safer comparison.

    Why this exists:
    In real systems a phone can be stored as:
    - 6861234567
    - 526861234567
    - +52 686 123 4567

    But the user might type only:
    - 6861234567

    So instead of strict one-format matching,
    we compare a few safe normalized variants.
    """

    normalized = normalize_phone(phone_value)

    variants = set()

    if normalized:
        variants.add(normalized)

    if normalized.startswith("52") and len(normalized) > 10:
        variants.add(normalized[2:])

    if len(normalized) > 10:
        variants.add(normalized[-10:])

    return variants


def validate_registration_fields(data):
    """
    Validate common registration fields.

    This helper keeps API and browser register validation consistent.
    """

    required_fields = [
        "first_name",
        "last_name",
        "username",
        "email",
        "phone",
        "password",
        "validation_code"
    ]

    for field in required_fields:
        if field not in data or not str(data[field]).strip():
            return False, f"{field} is required"

    role = normalize_role(data.get("role", "estudiante"))

    allowed_roles = {"estudiante", "docente", "personal", "administrativo"}

    if role not in allowed_roles:
        return False, "Invalid role"

    return True, None


def get_current_language():
    """
    Return the current UI language stored in session.

    Option A rule:
    The selected language is stored only in browser session.
    """

    language = str(session.get("language", "es")).strip().lower()

    if language not in {"en", "es"}:
        language = "es"

    return language


def save_language_from_request():
    """
    Save selected language from GET or POST into session.

    Supported values:
    - en
    - es
    """

    language = (
        request.args.get("language")
        or request.form.get("language")
        or session.get("language")
        or "es"
    )

    language = str(language).strip().lower()

    if language not in {"en", "es"}:
        language = "es"

    session["language"] = language
    return language


def get_login_text(language):
    """
    Return login page text according to selected language.
    """

    translations = {
        "es": {
            "page_title": "UniTrack Login",
            "card_title": "Acceso",
            "login_label": "Correo electrónico o nombre de usuario",
            "login_placeholder": "Ingresa tu correo o usuario",
            "password_label": "Contraseña",
            "password_placeholder": "Ingresa tu contraseña",
            "forgot_password": "¿Olvidaste tu contraseña?",
            "remember_me": "Recordarme",
            "login_button": "Acceder a UniTrack",
            "register_button": "Crear nueva cuenta",

            "header_upbc_short": "UPBC",
            "header_university": "Universidad Politécnica de Baja California",
            "language_selector_aria_label": "Selector de idioma",

            "header_logo_sep_alt": "SEP",
            "header_logo_baja_alt": "Baja California",
            "header_logo_utyp_alt": "UTyP",

            "footer_university_name": "Universidad Politécnica de Baja California",
            "footer_address_line_1": "Calle de la Claridad S/N",
            "footer_address_line_2": "Colonia Plutarco Elías Calles, Mexicali, Baja California, México CP. 21376",
            "footer_phone": "Tel. Conmutador: (52) 686-104-2727",
            "footer_link": "Ir al sitio web de UPBC",
            "footer_unitrack_alt": "Logo de UniTrack",
            "footer_upbc_alt": "Logo oficial de UPBC",
            "footer_copyright": "© Todos los derechos reservados de la Universidad Politécnica de Baja California"
        },
        "en": {
            "page_title": "UniTrack Login",
            "card_title": "Access",
            "login_label": "Email or username",
            "login_placeholder": "Enter your email or username",
            "password_label": "Password",
            "password_placeholder": "Enter your password",
            "forgot_password": "Forgot your password?",
            "remember_me": "Remember me",
            "login_button": "Access UniTrack",
            "register_button": "Create new account",

            "header_upbc_short": "UPBC",
            "header_university": "Polytechnic University of Baja California",
            "language_selector_aria_label": "Language selector",

            "header_logo_sep_alt": "SEP",
            "header_logo_baja_alt": "Baja California",
            "header_logo_utyp_alt": "UTyP",

            "footer_university_name": "Polytechnic University of Baja California",
            "footer_address_line_1": "Calle de la Claridad S/N",
            "footer_address_line_2": "Plutarco Elías Calles Neighborhood, Mexicali, Baja California, Mexico CP. 21376",
            "footer_phone": "Main phone: (52) 686-104-2727",
            "footer_link": "Go to the UPBC website",
            "footer_unitrack_alt": "UniTrack Logo",
            "footer_upbc_alt": "Official UPBC Logo",
            "footer_copyright": "© All rights reserved by the Polytechnic University of Baja California"
        }
    }

    return translations.get(language, translations["es"])


def get_register_text(language):
    """
    Return register page text according to selected language.
    """

    translations = {
        "es": {
            "page_title": "UniTrack Register",
            "card_title": "Registro",
            "first_name_label": "Nombre",
            "first_name_placeholder": "Nombre",
            "last_name_label": "Apellido",
            "last_name_placeholder": "Apellido",
            "username_label": "Nombre de usuario",
            "username_placeholder": "Nombre de usuario",
            "email_label": "Correo electrónico",
            "email_placeholder": "Correo electrónico",
            "phone_label": "Teléfono",
            "phone_placeholder": "Teléfono",
            "role_label": "Rol",
            "role_placeholder": "Selecciona tu rol",
            "role_student": "Student",
            "role_teacher": "Teacher",
            "role_staff": "Staff",
            "role_admin": "Admin",
            "validation_code_label": "Código de validación",
            "validation_code_placeholder": "Código de validación",
            "password_label": "Crear contraseña",
            "password_placeholder": "Crear contraseña",
            "confirm_password_label": "Confirmar contraseña",
            "confirm_password_placeholder": "Confirmar contraseña",
            "show_password": "Mostrar contraseña",
            "photo_label": "Foto de perfil",
            "photo_help": "Sube una imagen clara de perfil. Formatos permitidos: JPG, JPEG, PNG, WEBP.",
            "create_account_button": "Create Account",
            "already_have_account": "¿Ya tienes una cuenta?",
            "sign_in": "Sign in",
            "helper_note": "Every registration requires a valid university-issued validation code.",

            "header_upbc_short": "UPBC",
            "header_university": "Universidad Politécnica de Baja California",
            "language_selector_aria_label": "Selector de idioma",
            "header_logo_sep_alt": "SEP",
            "header_logo_baja_alt": "Baja California",
            "header_logo_utyp_alt": "UTyP",
            "footer_university_name": "Universidad Politécnica de Baja California",
            "footer_address_line_1": "Calle de la Claridad S/N",
            "footer_address_line_2": "Colonia Plutarco Elías Calles, Mexicali, Baja California, México CP. 21376",
            "footer_phone": "Tel. Conmutador: (52) 686-104-2727",
            "footer_copyright": "© Todos los derechos reservados de la Universidad Politécnica de Baja California"
        },
        "en": {
            "page_title": "UniTrack Register",
            "card_title": "Register",
            "first_name_label": "First Name",
            "first_name_placeholder": "First name",
            "last_name_label": "Last Name",
            "last_name_placeholder": "Last name",
            "username_label": "Username",
            "username_placeholder": "Username",
            "email_label": "Email",
            "email_placeholder": "Email",
            "phone_label": "Phone",
            "phone_placeholder": "Phone",
            "role_label": "Role",
            "role_placeholder": "Select your role",
            "role_student": "Student",
            "role_teacher": "Teacher",
            "role_staff": "Staff",
            "role_admin": "Admin",
            "validation_code_label": "Validation Code",
            "validation_code_placeholder": "Validation code",
            "password_label": "Create Password",
            "password_placeholder": "Create password",
            "confirm_password_label": "Confirm Password",
            "confirm_password_placeholder": "Confirm password",
            "show_password": "Show password",
            "photo_label": "Profile Photo",
            "photo_help": "Upload a clear profile image. Supported formats: JPG, JPEG, PNG, WEBP.",
            "create_account_button": "Create Account",
            "already_have_account": "Already have an account?",
            "sign_in": "Sign in",
            "helper_note": "Every registration requires a valid university-issued validation code.",

            "header_upbc_short": "UPBC",
            "header_university": "Polytechnic University of Baja California",
            "language_selector_aria_label": "Language selector",
            "header_logo_sep_alt": "SEP",
            "header_logo_baja_alt": "Baja California",
            "header_logo_utyp_alt": "UTyP",
            "footer_university_name": "Polytechnic University of Baja California",
            "footer_address_line_1": "Calle de la Claridad S/N",
            "footer_address_line_2": "Plutarco Elías Calles Neighborhood, Mexicali, Baja California, Mexico CP. 21376",
            "footer_phone": "Main phone: (52) 686-104-2727",
            "footer_copyright": "© All rights reserved by the Polytechnic University of Baja California"
        }
    }

    return translations.get(language, translations["es"])


def build_login_template_context(
    error=None,
    success_message=None,
    login_value="",
    remember_me=False,
    language=None
):
    """
    Build login page context safely.

    This keeps:
    - current language
    - translated texts
    - entered login value
    - remember me state
    - messages
    """

    language = language or get_current_language()

    return {
        "error": error,
        "success_message": success_message,
        "login_value": str(login_value or "").strip(),
        "remember_me": bool(remember_me),
        "current_language": language,
        "text": get_login_text(language)
    }


def build_register_template_context(
    form_data=None,
    error=None,
    success_message=None,
    language=None
):
    """
    Build register page context safely.

    This preserves entered values when validation fails.
    """

    form_data = form_data or {}
    language = language or get_current_language()

    return {
        "error": error,
        "success_message": success_message,
        "first_name": str(form_data.get("first_name", "")).strip(),
        "last_name": str(form_data.get("last_name", "")).strip(),
        "username": str(form_data.get("username", "")).strip(),
        "email": str(form_data.get("email", "")).strip(),
        "phone": str(form_data.get("phone", "")).strip(),
        "role": normalize_role(form_data.get("role", "")) if form_data.get("role") else "",
        "validation_code": str(form_data.get("validation_code", "")).strip(),
        "current_language": language,
        "text": get_register_text(language)
    }


def build_forgot_password_template_context(email="", phone="", error=None, success_message=None):
    """
    Build forgot-password page context safely.
    """

    return {
        "error": error,
        "success_message": success_message,
        "email": str(email or "").strip(),
        "phone": str(phone or "").strip()
    }


def build_reset_password_template_context(token="", error=None, success_message=None):
    """
    Build reset-password page context safely.

    Teaching idea:
    The page keeps the token hidden but still available
    during form submission.
    """

    return {
        "error": error,
        "success_message": success_message,
        "token": str(token or "").strip()
    }


def get_user_by_email_and_phone(email, phone):
    """
    Verify that email and phone belong to the same user.

    Security rule:
    Both values must match the same account.

    Professional improvement:
    I now use a case-insensitive email lookup and normalized phone check.
    This makes forgot-password much more reliable.
    """

    email = str(email or "").strip().lower()

    if not email or not phone:
        return None

    submitted_variants = get_phone_variants(phone)

    if not submitted_variants:
        return None

    user = User.query.filter(
        func.lower(User.email) == email
    ).first()

    if not user:
        return None

    stored_variants = get_phone_variants(user.phone)

    if not stored_variants:
        return None

    if submitted_variants.isdisjoint(stored_variants):
        return None

    return user


def route_exists(path):
    """
    Check whether a URL path exists in the current Flask app.

    Why this matters:
    Earlier the login redirect was hardcoded.
    If that page did not exist, users landed in the wrong place.

    Now we only redirect to routes that are actually registered.
    """

    path = str(path or "").strip()

    if not path:
        return False

    for rule in current_app.url_map.iter_rules():
        if rule.rule == path:
            return True

    return False


def is_auth_route(path):
    """
    Check if a path belongs to authentication pages/routes.

    Why this matters:
    After login we should NEVER redirect back to auth pages,
    otherwise users can enter redirect loops or recursion-like behavior.
    """

    path = str(path or "").strip()

    auth_paths = {
        "/auth/login-page",
        "/auth/login",
        "/auth/logout",
        "/auth/register-page",
        "/auth/register",
        "/auth/forgot-password",
        "/auth/reset-password",
        "/auth/change-password",
        "/auth/me"
    }

    return path in auth_paths or path.startswith("/auth/")


def resolve_first_available_route(candidates, fallback=None):
    """
    Return the first registered non-auth route from a list.

    Safety rule:
    We do NOT fall back to "/" automatically because many projects
    redirect "/" back to login, which can create redirect loops.
    """

    for candidate in candidates:
        if route_exists(candidate) and not is_auth_route(candidate):
            return candidate

    if fallback and route_exists(fallback) and not is_auth_route(fallback):
        return fallback

    return None


def get_safe_authenticated_redirect(user):
    """
    Return a safe non-auth redirect for an already authenticated user.

    Important loop fix:
    If no dashboard exists for the user's role yet,
    return None instead of "/" so the caller can avoid redirect recursion.
    """

    role = normalize_role(getattr(user, "role", ""))

    role_candidates = {
        "administrativo": [
            "/admin/dashboard",
            "/admin",
            "/dashboard",
            "/panel"
        ],
        "docente": [
            "/professor/dashboard",
            "/teacher/dashboard",
            "/docente/dashboard",
            "/dashboard",
            "/panel"
        ],
        "personal": [
            "/personal/dashboard",
            "/staff/dashboard",
            "/dashboard",
            "/panel"
        ],
        "estudiante": [
            "/student/dashboard",
            "/estudiante/dashboard",
            "/student/panel",
            "/estudiante/panel",
            "/dashboard",
            "/panel",
            "/home"
        ]
    }

    candidates = role_candidates.get(role, [
        "/dashboard",
        "/panel",
        "/home"
    ])

    return resolve_first_available_route(candidates, fallback=None)


def get_login_redirect_for_role(user):
    """
    Return a SAFE redirect path after browser login.

    Important fix:
    We no longer redirect to "/" when the real role dashboard
    is missing, because that can loop back to login-page.

    If no safe route exists yet, we use logout page flow fallback.
    """

    redirect_path = get_safe_authenticated_redirect(user)

    if redirect_path and not is_auth_route(redirect_path):
        return redirect_path

    return "/auth/logout"


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user through JSON API.

    IMPORTANT RULE:
    Every role requires a valid university-issued validation code.
    """

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    is_valid, validation_error = validate_registration_fields(data)

    if not is_valid:
        return jsonify({"success": False, "error": validation_error}), 400

    role = normalize_role(data.get("role", "estudiante"))
    validation_code_text = str(data.get("validation_code")).strip()

    valid, validation_code_object, error = validate_code_for_use(
        validation_code_text,
        selected_role=role
    )

    if not valid:
        return jsonify({"success": False, "error": error}), 403

    try:
        password_hash = hash_password(data["password"])

        user = create_user(
            first_name=str(data["first_name"]).strip(),
            last_name=str(data["last_name"]).strip(),
            username=str(data["username"]).strip(),
            email=str(data["email"]).strip().lower(),
            phone=str(data["phone"]).strip(),
            password_hash=password_hash,
            role=role
        )

        if hasattr(user, "ensure_user_id_code"):
            user.ensure_user_id_code()
            db.session.commit()

        mark_validation_code_as_used(validation_code_object, user.id)

        return jsonify({
            "success": True,
            "message": "User created successfully",
            "user": {
                "id": user.id,
                "user_id_code": getattr(user, "user_id_code", None),
                "first_name": user.first_name,
                "last_name": user.last_name,
                "username": user.username,
                "email": user.email,
                "phone": user.phone,
                "role": user.role,
                "must_change_password": user.must_change_password,
                "is_active_user": user.is_active_user
            }
        }), 201

    except ValueError as error:
        return jsonify({"success": False, "error": str(error)}), 400

    except Exception:
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "Unexpected error while creating user"
        }), 500


@auth_bp.route("/register-page", methods=["GET", "POST"])
def register_page():
    """
    Browser register page route.
    """

    language = save_language_from_request()

    if request.method == "GET":
        return render_template(
            "auth_register.html",
            **build_register_template_context(language=language)
        )

    form_data = {
        "first_name": request.form.get("first_name", ""),
        "last_name": request.form.get("last_name", ""),
        "username": request.form.get("username", ""),
        "email": request.form.get("email", ""),
        "phone": request.form.get("phone", ""),
        "role": request.form.get("role", ""),
        "validation_code": request.form.get("validation_code", ""),
    }

    password = str(request.form.get("password", "")).strip()
    confirm_password = str(request.form.get("confirm_password", "")).strip()

    browser_payload = {
        "first_name": form_data["first_name"],
        "last_name": form_data["last_name"],
        "username": form_data["username"],
        "email": form_data["email"],
        "phone": form_data["phone"],
        "role": form_data["role"],
        "password": password,
        "validation_code": form_data["validation_code"],
    }

    is_valid, validation_error = validate_registration_fields(browser_payload)

    if not is_valid:
        return render_template(
            "auth_register.html",
            **build_register_template_context(
                form_data=form_data,
                error=validation_error,
                language=language
            )
        )

    if password != confirm_password:
        return render_template(
            "auth_register.html",
            **build_register_template_context(
                form_data=form_data,
                error=(
                    "Password and confirm password do not match"
                    if language == "en"
                    else "La contraseña y la confirmación no coinciden"
                ),
                language=language
            )
        )

    validation_code_text = str(form_data["validation_code"]).strip()
    role = normalize_role(form_data["role"])

    valid, validation_code_object, error = validate_code_for_use(
        validation_code_text,
        selected_role=role
    )

    if not valid:
        return render_template(
            "auth_register.html",
            **build_register_template_context(
                form_data=form_data,
                error=error,
                language=language
            )
        )

    try:
        photo_path = None
        uploaded_photo = request.files.get("photo")

        if uploaded_photo and uploaded_photo.filename:
            original_filename = secure_filename(uploaded_photo.filename)

            if original_filename:
                upload_folder = os.path.join(
                    current_app.root_path,
                    "static",
                    "uploads",
                    "profile_photos"
                )
                os.makedirs(upload_folder, exist_ok=True)

                unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
                file_save_path = os.path.join(upload_folder, unique_filename)

                uploaded_photo.save(file_save_path)
                photo_path = f"uploads/profile_photos/{unique_filename}"

        password_hash = hash_password(password)

        user = create_user(
            first_name=str(form_data["first_name"]).strip(),
            last_name=str(form_data["last_name"]).strip(),
            username=str(form_data["username"]).strip(),
            email=str(form_data["email"]).strip().lower(),
            phone=str(form_data["phone"]).strip(),
            password_hash=password_hash,
            role=role,
            photo_path=photo_path
        )

        if hasattr(user, "ensure_user_id_code"):
            user.ensure_user_id_code()
            db.session.commit()

        mark_validation_code_as_used(validation_code_object, user.id)

        return render_template(
            "auth_login.html",
            **build_login_template_context(
                success_message=(
                    "Account created successfully. You can now sign in."
                    if language == "en"
                    else "Cuenta creada correctamente. Ahora puedes iniciar sesión."
                ),
                language=language
            )
        )

    except ValueError as error:
        return render_template(
            "auth_register.html",
            **build_register_template_context(
                form_data=form_data,
                error=str(error),
                language=language
            )
        )

    except Exception:
        db.session.rollback()
        return render_template(
            "auth_register.html",
            **build_register_template_context(
                form_data=form_data,
                error=(
                    "Unexpected error while creating user"
                    if language == "en"
                    else "Error inesperado al crear el usuario"
                ),
                language=language
            )
        )


@auth_bp.route("/login-page", methods=["GET", "POST"])
def login_page():
    """
    Browser login page route.

    Recursion protection:
    If a user is already authenticated and reaches this page again,
    do not render login again.
    Send the user directly to the correct dashboard/panel.
    """

    language = save_language_from_request()

    if current_user.is_authenticated:
        redirect_path = get_safe_authenticated_redirect(current_user)

        if redirect_path:
            return redirect(redirect_path)

        logout_user()
        return render_template(
            "auth_login.html",
            **build_login_template_context(
                error="Your role dashboard is not available yet. Please sign in again after the page is connected.",
                language=language
            )
        )

    if request.method == "GET":
        return render_template(
            "auth_login.html",
            **build_login_template_context(language=language)
        )

    login_value = str(request.form.get("login", "")).strip()
    password = str(request.form.get("password", "")).strip()
    remember_me = str(request.form.get("remember_me", "")).strip().lower() in {
        "on", "true", "1", "yes"
    }

    user, error = authenticate_user(login_value, password)

    if error:
        return render_template(
            "auth_login.html",
            **build_login_template_context(
                error=error,
                login_value=login_value,
                remember_me=remember_me,
                language=language
            )
        )

    login_user(user, remember=remember_me)
    update_last_login(user)

    redirect_path = get_safe_authenticated_redirect(user)

    if not redirect_path:
        logout_user()
        return render_template(
            "auth_login.html",
            **build_login_template_context(
                error="Your role dashboard is not available yet. Please connect the correct dashboard route first.",
                login_value=login_value,
                remember_me=remember_me,
                language=language
            )
        )

    return redirect(redirect_path)


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_page():
    """
    Browser forgot-password page route.

    Flow:
    GET  -> show forgot password form
    POST -> verify email + phone, then send reset email

    Important fix:
    If email sending fails, do NOT bypass the email flow by redirecting
    directly to reset-password. Show the real error so SMTP issues can be
    fixed properly.
    """

    if request.method == "GET":
        return render_template(
            "auth_forgot_password.html",
            **build_forgot_password_template_context()
        )

    email = str(request.form.get("email", "")).strip().lower()
    phone = str(request.form.get("phone", "")).strip()

    if not email or not phone:
        return render_template(
            "auth_forgot_password.html",
            **build_forgot_password_template_context(
                email=email,
                phone=phone,
                error="Email and phone number are required"
            )
        )

    user = get_user_by_email_and_phone(email, phone)

    if not user:
        return render_template(
            "auth_forgot_password.html",
            **build_forgot_password_template_context(
                email=email,
                phone=phone,
                error="The provided email and phone number do not match any account"
            )
        )

    if not user.is_active_user:
        return render_template(
            "auth_forgot_password.html",
            **build_forgot_password_template_context(
                email=email,
                phone=phone,
                error="This account is inactive"
            )
        )

    try:
        send_password_reset_email(user)

        return render_template(
            "auth_forgot_password.html",
            **build_forgot_password_template_context(
                success_message="Password reset email sent successfully. Please check your inbox."
            )
        )

    except Exception as error:
        current_app.logger.exception("Failed to send password reset email")

        return render_template(
            "auth_forgot_password.html",
            **build_forgot_password_template_context(
                email=email,
                phone=phone,
                error=f"Email error: {str(error)}"
            )
        )


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password_page():
    """
    Browser reset-password page route.

    Flow:
    GET  -> validate token and show new password form
    POST -> validate token again and save new password

    Security idea:
    The token must be verified on both GET and POST.
    That way the page is not trusted blindly.
    """

    if request.method == "GET":
        token = str(request.args.get("token", "")).strip()

        if not token:
            return render_template(
                "auth_reset_password.html",
                **build_reset_password_template_context(
                    error="Missing reset token"
                )
            )

        user, error = verify_password_reset_token(token)

        if error:
            return render_template(
                "auth_reset_password.html",
                **build_reset_password_template_context(
                    error=error
                )
            )

        return render_template(
            "auth_reset_password.html",
            **build_reset_password_template_context(token=token)
        )

    token = str(request.form.get("token", "")).strip()
    password = str(request.form.get("password", "")).strip()
    confirm_password = str(request.form.get("confirm_password", "")).strip()

    if not token:
        return render_template(
            "auth_reset_password.html",
            **build_reset_password_template_context(
                error="Missing reset token"
            )
        )

    user, error = verify_password_reset_token(token)

    if error:
        return render_template(
            "auth_reset_password.html",
            **build_reset_password_template_context(
                error=error
            )
        )

    if not password or not confirm_password:
        return render_template(
            "auth_reset_password.html",
            **build_reset_password_template_context(
                token=token,
                error="Password and confirm password are required"
            )
        )

    if password != confirm_password:
        return render_template(
            "auth_reset_password.html",
            **build_reset_password_template_context(
                token=token,
                error="Password and confirm password do not match"
            )
        )

    try:
        user.password_hash = hash_password(password)
        user.must_change_password = False

        db.session.commit()

        language = get_current_language()

        return render_template(
            "auth_login.html",
            **build_login_template_context(
                success_message=(
                    "Password updated successfully. You can now sign in with your new password."
                    if language == "en"
                    else "Contraseña actualizada correctamente. Ahora puedes iniciar sesión con tu nueva contraseña."
                ),
                language=language
            )
        )

    except Exception:
        db.session.rollback()
        return render_template(
            "auth_reset_password.html",
            **build_reset_password_template_context(
                token=token,
                error="Unexpected error while updating password"
            )
        )


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Log in a user with email or username.
    This route is for JSON/API clients.
    """

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    login_value = data.get("login")
    password = data.get("password")
    remember_me = bool(data.get("remember_me", False))

    user, error = authenticate_user(login_value, password)

    if error:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    login_user(user, remember=remember_me)
    update_last_login(user)

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {
            "id": user.id,
            "user_id_code": getattr(user, "user_id_code", None),
            "first_name": user.first_name,
            "last_name": user.last_name,
            "username": user.username,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "must_change_password": user.must_change_password,
            "is_active_user": user.is_active_user,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None
        }
    }), 200


@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    """
    Log out the current user.

    FIX:
    - supports GET for browser logout link/button
    - supports POST for API and form logout
    """

    logout_user()

    return redirect("/auth/login-page")


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    """
    Return current logged-in user information.
    """

    return jsonify({
        "success": True,
        "user": {
            "id": current_user.id,
            "user_id_code": getattr(current_user, "user_id_code", None),
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "username": current_user.username,
            "email": current_user.email,
            "phone": current_user.phone,
            "role": current_user.role,
            "must_change_password": current_user.must_change_password,
            "is_active_user": current_user.is_active_user,
            "photo_path": current_user.photo_path,
            "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
            "updated_at": current_user.updated_at.isoformat() if current_user.updated_at else None
        }
    }), 200


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    """
    Change password for the logged-in user.
    """

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    current_password = str(data.get("current_password", "")).strip()
    new_password = str(data.get("new_password", "")).strip()

    if not current_password or not new_password:
        return jsonify({
            "success": False,
            "error": "current_password and new_password are required"
        }), 400

    if not verify_password(current_user.password_hash, current_password):
        return jsonify({
            "success": False,
            "error": "Current password is incorrect"
        }), 401

    try:
        current_user.password_hash = hash_password(new_password)
        current_user.must_change_password = False

        db.session.commit()

        return jsonify({
            "success": True,
            "message": "Password changed successfully",
            "must_change_password": current_user.must_change_password
        }), 200

    except Exception:
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "Unexpected error while changing password"
        }), 500