"""Secure interactive administrator password reset for local maintenance."""
import os
import sys
from getpass import getpass

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from app.database import db
from app.models.user_model import User
from app.services.account_security_service import set_new_password
from app.services.email_service import send_password_changed_alert


def main():
    app = create_app()
    with app.app_context():
        username = input("Admin username: ").strip()
        admin = db.session.execute(db.select(User).where(User.username == username)).scalar_one_or_none()
        if not admin or admin.role != "administrativo":
            print("Administrator not found.")
            return
        new_password = getpass("New password: ")
        confirmation = getpass("Confirm new password: ")
        if new_password != confirmation:
            print("Passwords do not match.")
            return
        try:
            set_new_password(admin, new_password, force_change=True)
            db.session.commit()
        except ValueError as error:
            db.session.rollback()
            print(str(error))
            return
        except Exception:
            db.session.rollback()
            raise
        try:
            send_password_changed_alert(admin)
        except Exception:
            app.logger.exception("Maintenance password reset email could not be delivered")
        print("Admin temporary password set. Administrator must change it on sign-in.")


if __name__ == "__main__":
    main()
