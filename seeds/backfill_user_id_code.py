"""
backfill_user_id_code.py

Backfill permanent UniTrack public user IDs for existing users.

Format:
UT-UPBC-0001

Rules:
- only fill users that do not have user_id_code yet
- do not modify username
- do not modify unrelated data
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from app.database import db
from app.models.user_model import User


def build_user_id_code(user_id):
    return f"UT-UPBC-{str(user_id).zfill(4)}"


def backfill_user_id_codes():
    users = User.query.order_by(User.id.asc()).all()
    updated_count = 0

    for user in users:
        if getattr(user, "user_id_code", None):
            continue

        user.user_id_code = build_user_id_code(user.id)
        updated_count += 1

    db.session.commit()
    return updated_count, len(users)


if __name__ == "__main__":
    app = create_app()

    with app.app_context():
        updated_count, total_users = backfill_user_id_codes()
        print(f"Total users checked: {total_users}")
        print(f"User ID codes created: {updated_count}")
        print("Backfill completed successfully.")