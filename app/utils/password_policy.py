"""One consistent password policy across every UniTrack registration/reset path.

Existing accounts remain valid until they choose a replacement password.
"""
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 1024
BLOCKED_PASSWORDS = frozenset({
    "passwordpassword", "password123456789", "123456789012345",
    "adminadminadmin", "qwertyqwerty123", "contraseña123456",
    "iloveyouiloveyou", "changemechangeme",
})


def new_password_error(password, user=None):
    """A short explanation or None for an acceptable new password."""
    if not isinstance(password, str):
        return "La contraseña debe ser texto."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Usa al menos {MIN_PASSWORD_LENGTH} caracteres para la nueva contraseña."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"La contraseña debe tener como máximo {MAX_PASSWORD_LENGTH} caracteres."
    if not password.strip():
        return "La contraseña no puede contener únicamente espacios."
    simplified = "".join(c for c in password.casefold() if c.isalnum())
    if simplified in BLOCKED_PASSWORDS or len(set(password.casefold())) <= 2:
        return "La contraseña es demasiado predecible. Usa una frase de contraseña diferente."
    if user is not None:
        name = str(getattr(user, "username", "") or "").casefold()
        email = str(getattr(user, "email", "") or "").split("@", 1)[0].casefold()
        lowered = password.casefold()
        if any(k and len(k) >= 4 and k in lowered for k in (name, email)):
            return "No incluyas tu nombre de usuario ni tu correo en la contraseña."
    return None
