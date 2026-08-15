"""
reset_admin_password.py
"""

import os
import sys
from getpass import getpass

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app
from app.database import db


def main():
    app = create_app()

    with app.app_context():

        username = input("Admin username: ").strip()

        admin = db.session.execute(
            text("""
                SELECT id, username, email, role
                FROM users
                WHERE username = :username
            """),
            {"username": username},
        ).fetchone()

        if not admin:
            print("User not found.")
            return

        if admin.role != "admin":
            print(f"Warning: this user has role '{admin.role}', not 'admin'.")
            return

        print()
        print(f"Admin found: {admin.username}")
        print(f"Email: {admin.email}")
        print()

        new_password = getpass("New password: ")
        confirm_password = getpass("Confirm new password: ")

        if new_password != confirm_password:
            print("Passwords do not match.")
            return

        if len(new_password) < 8:
            print("Password must contain at least 8 characters.")
            return

        new_hash = generate_password_hash(new_password)

        db.session.execute(
            text("""
                UPDATE users
                SET password_hash = :password_hash
                WHERE id = :user_id
            """),
            {"password_hash": new_hash, "user_id": admin.id},
        )

        db.session.commit()

        print()
        print("Admin password updated successfully.")


if __name__ == "__main__":
    main()
