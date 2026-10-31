"""Strict profile-photo validation and safe, metadata-free image storage.

All registration and role settings routes use this one entrypoint.
Existing photo files remain valid and are never removed during this migration.
"""
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from flask import current_app
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.utils import secure_filename

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 12_000_000
MAX_IMAGE_DIMENSION = 6000
OUTPUT_DIMENSION = 1024
VALID_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "gif"}
VALID_FORMATS = {"JPEG", "PNG", "WEBP", "GIF"}


def save_profile_photo(uploaded_file, *, kind="profile"):
    """Save a verified, re-encoded JPEG and return its app/static relative path.

    The caller must commit the user record, or call delete_profile_photo()
    if its database transaction fails.
    """
    filename = secure_filename(getattr(uploaded_file, "filename", "") or "")
    if not filename or "." not in filename:
        raise ValueError("Selecciona un archivo de imagen válido.")
    extension = filename.rsplit(".", 1)[-1].lower()
    if extension not in VALID_EXTENSIONS:
        raise ValueError("Formato inválido. Usa JPG, PNG, WEBP o GIF.")

    content = uploaded_file.stream.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise ValueError("El archivo de imagen está vacío.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("La imagen supera el límite de 5 MB.")

    try:
        with Image.open(BytesIO(content)) as source:
            if source.format not in VALID_FORMATS:
                raise ValueError("El contenido no es una imagen compatible.")
            width, height = source.size
            if (width <= 0 or height <= 0 or
                    width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION or
                    width * height > MAX_IMAGE_PIXELS):
                raise ValueError("La imagen tiene dimensiones demasiado grandes.")

            # Force a full decode before writing any file. This catches
            # corrupted images and rejects scripts disguised as .jpg/.png.
            source.load()
            image = ImageOps.exif_transpose(source)
            image.thumbnail((OUTPUT_DIMENSION, OUTPUT_DIMENSION), Image.Resampling.LANCZOS)
            if image.mode in {"RGBA", "LA"} or "transparency" in image.info:
                rgba = image.convert("RGBA")
                flattened = Image.new("RGB", rgba.size, (255, 255, 255))
                flattened.paste(rgba, mask=rgba.getchannel("A"))
                image = flattened
            else:
                image = image.convert("RGB")

            output = BytesIO()
            # Metadata, embedded comments and animation are intentionally dropped.
            image.save(output, format="JPEG", quality=86, optimize=True)
            clean_data = output.getvalue()
    except (UnidentifiedImageError, OSError, SyntaxError, OverflowError,
            Image.DecompressionBombError) as exc:
        raise ValueError("No se pudo verificar la imagen. Selecciona una foto válida.") from exc

    # The original name is never used in the final path.
    safe_kind = "".join(c for c in str(kind) if c.isascii() and c.isalnum())[:24] or "profile"
    relative_path = f"uploads/profile_photos/{safe_kind}_{uuid4().hex}.jpg"
    destination = Path(current_app.static_folder) / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Unique name, exclusive creation: no overwrites of existing user photos.
    with destination.open("xb") as target:
        target.write(clean_data)
    return relative_path


def delete_profile_photo(relative_path):
    """Discard only a newly created photo if a later DB commit fails."""
    prefix = "uploads/profile_photos/"
    if not relative_path or not relative_path.startswith(prefix):
        return
    path = Path(current_app.static_folder) / relative_path
    try:
        path.unlink(missing_ok=True)
    except OSError:
        current_app.logger.exception("Failed to discard uncommitted profile photo")
