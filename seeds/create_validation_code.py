"""
create_validation_code.py
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ✅ ONLY REQUIRED MODEL
import app.models.validation_code_model

from sqlalchemy import text

from app import create_app
from app.database import db
from app.services.validation_code_service import create_validation_code


ALLOWED_ROLES = {
    "estudiante",
    "docente",
    "personal",
    "administrativo",
}


def normalize_role(role_value):
    return str(role_value or "").strip().lower()


def main():
    app = create_app()

    with app.app_context():

        admin_user_row = db.session.execute(
            text("""
                SELECT id
                FROM users
                WHERE role = :role
                LIMIT 1
            """),
            {"role": "administrativo"}
        ).fetchone()

        if not admin_user_row:
            print("❌ ERROR: No admin user found.")
            return

        admin_user_id = admin_user_row[0]

        print("Available roles:")
        print("- estudiante")
        print("- docente")
        print("- personal")
        print("- administrativo")

        selected_role = normalize_role(input("Enter role for this validation code: "))

        if selected_role not in ALLOWED_ROLES:
            print("❌ ERROR: Invalid role.")
            return

        validation_code = create_validation_code(
            generated_by_user_id=admin_user_id,
            role=selected_role,
            expires_in_hours=24
        )

        print("✅ Validation code created successfully")
        print(f"👉 CODE: {validation_code.code}")
        print(f"Role: {validation_code.role}")
        print(f"Expires at: {validation_code.expires_at}")


if __name__ == "__main__":
    main()