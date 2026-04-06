"""
check_users.py
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sqlalchemy import text

from app import create_app
from app.database import db


def main():
    app = create_app()

    with app.app_context():
        rows = db.session.execute(text("""
            SELECT id, first_name, last_name, username, email, role
            FROM users
            ORDER BY id
        """)).fetchall()

        if not rows:
            print("No users found.")
            return

        print("Users in database:")
        print("-" * 80)

        for row in rows:
            print(
                f"ID: {row[0]} | "
                f"Name: {row[1]} {row[2]} | "
                f"Username: {row[3]} | "
                f"Email: {row[4]} | "
                f"Role: {row[5]}"
            )


if __name__ == "__main__":
    main()