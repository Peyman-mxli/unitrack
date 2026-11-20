"""Permanently reset a LOCAL UniTrack SQLite installation to one new admin.

Run with the Flask server STOPPED:
    python scripts/reset_all_users.py

This intentionally deletes ALL local application data, not just user rows.
It does not affect GitHub, another computer, hosted PostgreSQL or backups.
"""
from __future__ import annotations

from getpass import getpass
from pathlib import Path
import os
import shutil
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
DATABASE = ROOT / "unitrack.db"
CONFIRMATION = "DELETE ALL UNITRACK USERS"


def main() -> int:
    if (
        os.environ.get("DATABASE_URL")
        or os.environ.get("UNITRACK_ENV", "").strip().lower() == "production"
        or os.environ.get("RENDER_SERVICE_ID")
        or os.environ.get("RENDER_EXTERNAL_HOSTNAME")
        or os.environ.get("RENDER", "").lower() == "true"
    ):
        raise SystemExit("Refusing to reset a hosted/production or DATABASE_URL installation.")
    if not DATABASE.is_file() or DATABASE.is_symlink():
        raise SystemExit(f"Existing local SQLite database not found: {DATABASE}")
    if not (ROOT / "run.py").is_file():
        raise SystemExit("Not a UniTrack project directory.")

    sys.path.insert(0, str(ROOT))
    from app.utils.password_policy import new_password_error

    print("WARNING: This permanently removes ALL local UniTrack database records:")
    print("admins, students, teachers, staff, QR scans, history, notices and settings.")
    print("It also removes local uploaded profile photos. It does NOT erase backups.")
    print(f"Database: {DATABASE}")
    response = input(f"Type {CONFIRMATION!r} to continue: ").strip()
    if response != CONFIRMATION:
        print("Canceled; nothing changed.")
        return 1

    new_password = getpass("New Admin password (8+ characters): ")
    error = new_password_error(new_password)
    if error:
        raise SystemExit(error)
    if new_password != getpass("Confirm new Admin password: "):
        raise SystemExit("Passwords do not match; nothing changed.")

    # Verify a real UniTrack database, and refuse if another process holds it.
    # Exclusive locking also prevents deleting the SQLite WAL underneath a server.
    try:
        connection = sqlite3.connect(str(DATABASE), timeout=1, isolation_level=None)
        try:
            connection.execute("BEGIN EXCLUSIVE")
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
            ).fetchone()
            if not exists:
                raise RuntimeError("This file has no UniTrack users table.")
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise RuntimeError("SQLite integrity check failed.")
            connection.execute("ROLLBACK")
        finally:
            connection.close()
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        raise SystemExit(f"Reset canceled. Stop UniTrack and check the database: {exc}")

    # The user explicitly requested permanent removal, without archiving this DB.
    # Clean associated SQLite sidecars only after verifying no active writer.
    for suffix in ("-wal", "-shm", ""):
        file = Path(str(DATABASE) + suffix)
        if file.exists():
            file.unlink()

    old_initial_password = os.environ.get("UNITRACK_INITIAL_ADMIN_PASSWORD")
    try:
        os.environ["UNITRACK_INITIAL_ADMIN_PASSWORD"] = new_password
        from app import create_app
        from app.database import db
        from app.models.user_model import User

        app = create_app()
        with app.app_context():
            accounts = db.session.execute(db.select(User)).scalars().all()
            if len(accounts) != 1 or accounts[0].username != "Admin":
                raise RuntimeError("Fresh database did not contain exactly one Admin.")
    finally:
        if old_initial_password is None:
            os.environ.pop("UNITRACK_INITIAL_ADMIN_PASSWORD", None)
        else:
            os.environ["UNITRACK_INITIAL_ADMIN_PASSWORD"] = old_initial_password
        new_password = None

    # Only user-upload directories are cleared; packaged static images stay.
    for relative in (
        "private_uploads/profile_photos",
        "app/static/uploads",
        "app/static/img/profiles",
        "app/routes/static/uploads",
    ):
        folder = ROOT / relative
        if folder.is_symlink():
            raise RuntimeError(f"Refusing to follow symlink in uploads: {folder}")
        if folder.is_dir():
            shutil.rmtree(folder)

    print("RESET COMPLETE: All old local accounts and QR history removed.")
    print("New account: Admin")
    print("Sign in using the password you entered; change it when prompted.")
    print("Backups, other laptop data, and hosted data were not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
