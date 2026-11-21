"""Integration smoke tests against an isolated temporary SQLite database."""
import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta


class UniTrackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix="unitrack-tests-")
        os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(cls.folder.name, "test.db").replace("\\", "/")
        os.environ["FLASK_DEBUG"] = "False"
        os.environ.pop("UNITRACK_INITIAL_ADMIN_PASSWORD", None)
        from app import create_app
        from app.database import db
        from app.models.user_model import User
        from app.models.academic_models import (
            UniversityClass, ClassEnrollment, ClassMeeting, ClassAttendance
        )
        from werkzeug.security import generate_password_hash
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.db = db
        with cls.app.app_context():
            for username, role in [("Admin", "administrativo"), ("StudentA", "estudiante"),
                                   ("TeacherA", "docente"), ("StaffA", "personal")]:
                db.session.add(User(
                    username=username, email=username.lower() + "@example.test",
                    first_name=username, last_name="Test", phone="0000000000",
                    role=role, language="es",
                    password_hash=generate_password_hash("TestingPassword123!"),
                    is_active_user=True,
                ))
            db.session.commit()

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            cls.db.session.remove()
            cls.db.engine.dispose()
        cls.folder.cleanup()

    def test_admin_mfa_enrollment_challenge_and_one_use_recovery(self):
        """Enrolled administrators need an authenticator or unused backup code."""
        import time
        from app.models.admin_mfa_model import AdminMFA, AdminMFARecoveryCode
        from app.models.user_model import User
        from app.services.admin_mfa_service import decrypt_secret, current_totp
        try:
            admin = self._signed_in_client("Admin")
            start = admin.get("/auth/admin-2fa/setup")
            self.assertEqual(start.status_code, 200)
            self.assertIn(b"otpauth", start.data.replace(b" ", b"").lower() + b"otpauth")
            token = re.search(rb'name="csrf_token" value="([^"]+)"', start.data).group(1).decode()
            with self.app.app_context():
                user = self.db.session.execute(self.db.select(User).where(User.username=="Admin")).scalar_one()
                record = self.db.session.get(AdminMFA, user.id)
                self.assertIsNotNone(record)
                self.assertIsNone(record.enabled_at)
                otp = current_totp(decrypt_secret(record.encrypted_secret), int(time.time())//30)
            enable = admin.post("/auth/admin-2fa/setup", data={"csrf_token": token, "code": otp})
            self.assertEqual(enable.status_code, 200)
            codes = re.findall(rb"[A-F0-9]{4}(?:-[A-F0-9]{4}){3}", enable.data)
            self.assertEqual(len(codes), 8)
            self.assertEqual(admin.get("/admin/dashboard").status_code, 200)

            another = self._signed_in_client("Admin")
            locked = another.get("/admin/dashboard")
            self.assertEqual(locked.status_code, 302)
            self.assertIn("/auth/admin-2fa/verify", locked.headers["Location"])
            challenge = another.get("/auth/admin-2fa/verify")
            self.assertEqual(challenge.status_code, 200)
            token = re.search(rb'name="csrf_token" value="([^"]+)"', challenge.data).group(1).decode()
            recovered = another.post("/auth/admin-2fa/verify", data={
                "csrf_token": token, "code": codes[0].decode()
            })
            self.assertEqual(recovered.status_code, 302)
            self.assertEqual(another.get("/admin/dashboard").status_code, 200)

            replay = self._signed_in_client("Admin")
            page = replay.get("/auth/admin-2fa/verify")
            token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
            self.assertEqual(replay.post("/auth/admin-2fa/verify", data={
                "csrf_token": token, "code": codes[0].decode()
            }).status_code, 400)
        finally:
            with self.app.app_context():
                user = self.db.session.execute(self.db.select(User).where(User.username=="Admin")).scalar_one()
                self.db.session.execute(self.db.delete(AdminMFARecoveryCode).where(
                    AdminMFARecoveryCode.user_id == user.id
                ))
                record = self.db.session.get(AdminMFA, user.id)
                if record:
                    self.db.session.delete(record)
                self.db.session.commit()

    def test_admin_mfa_production_enrollment_policy_and_totp_replay(self):
        from app.services.admin_mfa_service import (
            new_totp_secret, current_totp, verify_totp, encrypt_secret, decrypt_secret
        )
        secret = new_totp_secret()
        with self.app.app_context():
            self.assertEqual(decrypt_secret(encrypt_secret(secret)), secret)
        now = 1_700_000_000
        counter = now // 30
        code = current_totp(secret, counter)
        self.assertEqual(verify_totp(secret, code, now=now), counter)
        self.assertIsNone(verify_totp(secret, code, last_counter=counter, now=now))
        self.assertIsNone(verify_totp(secret, "123;DROP TABLE", now=now))

        previous = self.app.config.get("ADMIN_MFA_REQUIRED")
        self.app.config["ADMIN_MFA_REQUIRED"] = True
        try:
            admin = self._signed_in_client("Admin")
            response = admin.get("/admin/dashboard")
            self.assertEqual(response.status_code, 302)
            self.assertIn("/auth/admin-2fa/setup", response.headers["Location"])
        finally:
            self.app.config["ADMIN_MFA_REQUIRED"] = previous

    def test_strong_new_password_policy_and_exact_hashing(self):
        """New passwords have a policy, but existing legacy hashes still verify."""
        from app.utils.password_policy import new_password_error
        from app.utils.security import hash_password, verify_password
        self.assertIsNotNone(new_password_error("short"))
        self.assertIsNotNone(new_password_error("Ab3!7xy"))  # 7 characters
        self.assertIsNone(new_password_error("Qz8!4nPr"))  # 8 characters
        self.assertIsNotNone(new_password_error("password123456789"))
        good = "a strong unique passphrase with spaces!"
        self.assertIsNone(new_password_error(good))
        exact = " " + good + " "
        stored = hash_password(exact)
        self.assertTrue(stored.startswith("scrypt:"))
        self.assertTrue(verify_password(stored, exact))
        self.assertFalse(verify_password(stored, good))
        self.assertFalse(verify_password(stored, exact.strip()))

        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "192.0.2.91"
        rejected = client.post("/auth/register", json={
            "first_name": "Security", "last_name": "Check", "username": "SecurityTest",
            "email": "security@example.test", "phone": "6861234567",
            "password": "short", "role": "estudiante",
            "validation_code": "invalid"
        })
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("8", rejected.get_json()["error"])

    def test_required_password_change_prevents_dashboard_until_changed(self):
        """A temporary admin-assigned password cannot unlock normal pages."""
        from app.models.user_model import User
        from werkzeug.security import check_password_hash
        with self.app.app_context():
            account = self.db.session.execute(self.db.select(User).where(User.username=="StudentA")).scalar_one()
            original_hash = account.password_hash
            account.must_change_password = True
            self.db.session.commit()
        try:
            student = self._signed_in_client("StudentA")
            denied = student.get("/student/dashboard")
            self.assertEqual(denied.status_code, 302)
            self.assertIn("/auth/change-password-page", denied.headers["Location"])
            page = student.get("/auth/change-password-page")
            self.assertEqual(page.status_code, 200)
            csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
            form = {
                "csrf_token": csrf,
                "current_password": "TestingPassword123!",
                "new_password": "An especially unique password phrase 2026!",
                "confirm_password": "An especially unique password phrase 2026!",
            }
            short = student.post("/auth/change-password-page", data={
                **form, "new_password": "short", "confirm_password": "short"
            })
            self.assertEqual(short.status_code, 400)
            result = student.post("/auth/change-password-page", data=form)
            self.assertEqual(result.status_code, 302)
            self.assertIn("/student/dashboard", result.headers["Location"])
            self.assertEqual(student.get("/student/dashboard").status_code, 200)
            with self.app.app_context():
                account = self.db.session.execute(self.db.select(User).where(User.username=="StudentA")).scalar_one()
                self.assertFalse(account.must_change_password)
                self.assertTrue(check_password_hash(account.password_hash, form["new_password"]))
        finally:
            with self.app.app_context():
                account = self.db.session.execute(self.db.select(User).where(User.username=="StudentA")).scalar_one()
                account.password_hash = original_hash
                account.must_change_password = False
                self.db.session.commit()

    def test_password_change_revokes_other_sessions_and_json_requires_csrf(self):
        """Old sessions fail after reset; authenticated JSON mutations need CSRF."""
        from app.models.user_model import User
        with self.app.app_context():
            account = self.db.session.execute(self.db.select(User).where(User.username=="StudentA")).scalar_one()
            original_hash = account.password_hash
        try:
            first = self._signed_in_client("StudentA")
            other = self._signed_in_client("StudentA")
            token = first.get("/auth/me").get_json()["csrf_token"]
            payload = {
                "current_password": "TestingPassword123!",
                "new_password": "Securely updated password phrase 2026!"
            }
            no_token = first.post("/auth/change-password", json=payload)
            self.assertEqual(no_token.status_code, 400)
            wrong_origin = first.post("/auth/change-password", json=payload, headers={
                "Origin": "https://untrusted.example", "X-CSRF-Token": token
            })
            self.assertEqual(wrong_origin.status_code, 403)
            changed = first.post("/auth/change-password", json=payload, headers={
                "X-CSRF-Token": token
            })
            self.assertEqual(changed.status_code, 200)
            self.assertEqual(first.get("/student/dashboard").status_code, 200)
            kicked = other.get("/student/dashboard")
            self.assertEqual(kicked.status_code, 302)
            self.assertIn("/auth/login-page", kicked.headers["Location"])
        finally:
            with self.app.app_context():
                account = self.db.session.execute(self.db.select(User).where(User.username=="StudentA")).scalar_one()
                account.password_hash = original_hash
                account.must_change_password = False
                self.db.session.commit()

    def test_login_and_password_recovery_do_not_reveal_account_existence(self):
        """Error feedback may not identify which email addresses have accounts."""
        from unittest.mock import patch
        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "192.0.2.92"
        first = client.get("/auth/login-page")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', first.data).group(1).decode()
        nonexistent = client.post("/auth/login-page", data={
            "login": "nosuchuser@example.test", "password": "bad",
            "csrf_token": token
        })
        exists = client.post("/auth/login-page", data={
            "login": "StudentA", "password": "bad", "csrf_token": token
        })
        self.assertEqual(nonexistent.status_code, 200)
        self.assertEqual(exists.status_code, 200)
        self.assertIn(b"Invalid login credentials", nonexistent.data)
        self.assertIn(b"Invalid login credentials", exists.data)

        with patch("app.routes.auth_routes.send_password_reset_email", return_value=None):
            matches = client.post("/auth/forgot-password", data={
                "email": "studenta@example.test", "phone": "0000000000",
                "csrf_token": token
            })
            absent = client.post("/auth/forgot-password", data={
                "email": "notregistered@example.test", "phone": "0000000000",
                "csrf_token": token
            })
        self.assertEqual(matches.status_code, 200)
        self.assertEqual(absent.status_code, 200)
        self.assertIn("Si los datos coinciden".encode(), matches.data)
        self.assertIn("Si los datos coinciden".encode(), absent.data)

    def test_five_failures_email_approval_and_five_fresh_attempts(self):
        """Five bad guesses lock across aliases; GET cannot consume approval."""
        from unittest.mock import patch
        from app.models.user_model import User
        from app.models.login_security_model import LoginSecurityState
        from urllib.parse import quote
        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "192.0.2.215"
        with self.app.app_context():
            user = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            user_id = user.id
            self.db.session.execute(
                self.db.delete(LoginSecurityState).where(LoginSecurityState.user_id == user_id)
            )
            self.db.session.commit()
        try:
            with patch("app.routes.auth_routes.send_login_lock_alert") as alert:
                for attempt in range(5):
                    response = client.post("/auth/login", json={
                        "login": "StudentA" if attempt % 2 else "studenta@example.test",
                        "password": "wrong-password",
                    })
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.get_json()["error"], "Invalid login credentials")
                self.assertEqual(alert.call_count, 1)
                token = alert.call_args.args[1]

                correct_but_locked = client.post("/auth/login", json={
                    "login": "StudentA", "password": "TestingPassword123!"
                })
                self.assertEqual(correct_but_locked.status_code, 401)
                approval_page = client.get("/auth/unlock-login?token=" + quote(token))
                self.assertEqual(approval_page.status_code, 200)
                self.assertIn(b"Desbloquear cuenta", approval_page.data)
                csrf = re.search(
                    rb'name="csrf_token" value="([^"]+)"', approval_page.data
                ).group(1).decode()

                # Link scanners and cross-site POSTs cannot approve unlock.
                self.assertEqual(
                    client.post("/auth/unlock-login", data={"token": token}).status_code, 400
                )
                approved = client.post("/auth/unlock-login", data={
                    "token": token, "csrf_token": csrf
                })
                self.assertEqual(approved.status_code, 200)
                self.assertEqual(
                    client.post("/auth/unlock-login", data={
                        "token": token, "csrf_token": csrf
                    }).status_code, 400
                )

                # Approval grants a fresh five guesses; no automatic sign-in.
                for attempt in range(5):
                    response = client.post("/auth/login", json={
                        "login": "StudentA", "password": "wrong-password"
                    })
                    self.assertEqual(response.status_code, 401)
                self.assertEqual(alert.call_count, 2)
                self.assertEqual(client.post("/auth/login", json={
                    "login": "StudentA", "password": "TestingPassword123!"
                }).status_code, 401)
                with self.app.app_context():
                    state = self.db.session.get(LoginSecurityState, user_id)
                    self.assertEqual(state.failed_attempts, 5)
                    self.assertIsNotNone(state.locked_until)
        finally:
            with self.app.app_context():
                self.db.session.execute(self.db.delete(LoginSecurityState).where(
                    LoginSecurityState.user_id == user_id
                ))
                self.db.session.commit()

    def test_password_history_rejects_previous_passwords_after_multiple_changes(self):
        """An account cannot revert to an earlier password, even via JSON API."""
        from unittest.mock import patch
        from app.models.user_model import User
        from app.models.password_history_model import PasswordHistory
        with self.app.app_context():
            user = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            original_hash = user.password_hash
            user_id = user.id
        candidate_a = "Account history example phrase number A 2026!"
        candidate_b = "Account history example phrase number B 2026!"
        try:
            client = self._signed_in_client("StudentA")
            csrf = client.get("/auth/me").get_json()["csrf_token"]
            def change(new_password, old_password):
                return client.post("/auth/change-password", json={
                    "current_password": old_password, "new_password": new_password
                }, headers={"X-CSRF-Token": csrf})
            with patch("app.routes.auth_routes.send_password_changed_alert"):
                self.assertEqual(change(candidate_a, "TestingPassword123!").status_code, 200)
                self.assertEqual(change(candidate_b, candidate_a).status_code, 200)
                first_reuse = change(candidate_a, candidate_b)
                self.assertEqual(first_reuse.status_code, 400)
                self.assertIn("anterior", first_reuse.get_json()["error"])
                older_reuse = change("TestingPassword123!", candidate_b)
                self.assertEqual(older_reuse.status_code, 400)
                self.assertIn("anterior", older_reuse.get_json()["error"])
        finally:
            with self.app.app_context():
                user = self.db.session.get(User, user_id)
                user.password_hash = original_hash
                self.db.session.execute(self.db.delete(PasswordHistory).where(
                    PasswordHistory.user_id == user_id
                ))
                self.db.session.commit()

    def test_email_never_sends_credentials_without_tls(self):
        from unittest.mock import patch
        from app.services.email_service import send_email
        with self.app.app_context():
            with patch.dict(self.app.config, {
                "MAIL_USERNAME": "sender@example.test",
                "MAIL_PASSWORD": "test-only-password",
                "MAIL_DEFAULT_SENDER": "sender@example.test",
                "MAIL_SERVER": "smtp.example.test",
                "MAIL_USE_TLS": False,
                "MAIL_USE_SSL": False,
            }):
                with patch("smtplib.SMTP") as smtp:
                    with self.assertRaisesRegex(ValueError, "without TLS"):
                        send_email("recipient@example.test", "Test", "Message")
                    smtp.assert_not_called()

    def test_database_health_creates_verified_backup_without_changing_rows(self):
        """Audit the isolated test database and verify a complete private snapshot."""
        from pathlib import Path
        from contextlib import closing
        from unittest.mock import patch
        import hashlib
        import json
        import sqlite3
        from scripts import database_health

        database = Path(self.folder.name) / "test.db"
        with closing(sqlite3.connect(str(database))) as source:
            original_users = source.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            original_tables = source.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0]
        self.assertEqual(
            database_health.main(["--database", str(database), "--schema", "--strict"]), 0
        )
        with tempfile.TemporaryDirectory(prefix="unitrack-backup-test-") as directory:
            with patch.object(database_health, "BACKUP_FOLDER", Path(directory)):
                self.assertEqual(
                    database_health.main(["--database", str(database), "--backup"]), 0
                )
            backups = list(Path(directory).glob("*.db"))
            self.assertEqual(len(backups), 1)
            snapshot = backups[0]
            manifest = json.loads(snapshot.with_suffix(".json").read_text("utf-8"))
            self.assertEqual(manifest["filename"], snapshot.name)
            self.assertEqual(manifest["sha256"], hashlib.sha256(snapshot.read_bytes()).hexdigest())
            self.assertEqual(manifest["table_counts"]["users"], original_users)
            with closing(sqlite3.connect(str(snapshot))) as saved:
                self.assertEqual(saved.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(saved.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                                 original_users)
        with closing(sqlite3.connect(str(database))) as source:
            self.assertEqual(source.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                             original_users)
            self.assertEqual(source.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0], original_tables)

    def test_database_health_detects_missing_corrupt_and_outdated_schema(self):
        """Never create/repair the real database when a check fails."""
        import sqlite3
        from pathlib import Path
        from contextlib import closing
        from scripts import database_health

        with tempfile.TemporaryDirectory(prefix="unitrack-health-check-") as folder:
            root = Path(folder)
            missing = root / "missing.db"
            self.assertEqual(database_health.main(["--database", str(missing)]), 1)
            self.assertFalse(missing.exists())
            corrupt = root / "corrupt.db"
            corrupt.write_bytes(b"not a valid SQLite database")
            self.assertEqual(database_health.main(["--database", str(corrupt)]), 1)
            partial = root / "old.db"
            with closing(sqlite3.connect(str(partial))) as conn:
                conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
            self.assertEqual(
                database_health.main(["--database", str(partial), "--schema", "--strict"]), 2
            )
            # The same audit can report problems without blocking the developer.
            self.assertEqual(
                database_health.main(["--database", str(partial), "--schema"]), 0
            )
            with closing(sqlite3.connect(str(partial))) as conn:
                self.assertEqual(conn.execute("PRAGMA table_info(users)").fetchall()[0][1],
                                 "id")
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                ).fetchone()[0], 1)

    def test_public_contact_form_stores_messages_and_admin_can_review_them(self):
        """Public visitors can send questions/bugs, admins receive them privately."""
        from app.models.contact_message_model import ContactMessage
        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "203.0.113.197"
        page = client.get("/?lang=es")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Envíanos un mensaje".encode("utf-8"), page.data)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(token)
        form = {
            "csrf_token": token.group(1).decode(),
            "name": "Persona de prueba",
            "email": "persona@example.test",
            "category": "error",
            "message": "El lector QR no detecta el código al abrir la cámara.",
        }
        response = client.post("/contacto/enviar", data=form)
        self.assertEqual(response.status_code, 303)
        self.assertIn("#contacto", response.headers["Location"])
        follow = client.get(response.headers["Location"])
        self.assertEqual(follow.status_code, 200)
        self.assertIn("Mensaje enviado correctamente".encode("utf-8"), follow.data)
        self.assertNotIn("Mensaje enviado correctamente".encode("utf-8"), client.get("/").data)

        with self.app.app_context():
            record = self.db.session.execute(
                self.db.select(ContactMessage).where(
                    ContactMessage.email == "persona@example.test"
                )
            ).scalar_one()
            contact_id = record.id
            self.assertEqual(record.status, "new")
            self.assertEqual(record.category, "error")

        self.assertIn(client.get("/admin/contact-messages").status_code, (302, 401))
        student = self._signed_in_client("StudentA")
        self.assertNotEqual(student.get("/admin/contact-messages").status_code, 200)
        admin = self._signed_in_client("Admin")
        inbox = admin.get("/admin/contact-messages")
        self.assertEqual(inbox.status_code, 200)
        self.assertIn(b"persona@example.test", inbox.data)
        self.assertIn("El lector QR no detecta".encode(), inbox.data)
        self.assertIn(b"/admin/contact-messages", admin.get("/admin/dashboard").data)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', inbox.data)
        self.assertIsNotNone(csrf)
        change = admin.post(
            f"/admin/contact-messages/{contact_id}/status",
            data={"csrf_token": csrf.group(1).decode(), "status": "reviewed"}
        )
        self.assertEqual(change.status_code, 302)
        with self.app.app_context():
            self.assertEqual(
                self.db.session.get(ContactMessage, contact_id).status, "reviewed"
            )
        filtered = admin.get("/admin/contact-messages?status=reviewed")
        self.assertIn(b"persona@example.test", filtered.data)

    def test_public_contact_rejects_invalid_and_unsafe_submissions(self):
        """CSRF, validation, honeypot and HTML escaping protect public reports."""
        from app.models.contact_message_model import ContactMessage
        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "203.0.113.198"
        invalid = client.post("/contacto/enviar", data={
            "name": "Someone", "email": "user@example.test",
            "category": "error", "message": "Something is broken."
        })
        self.assertEqual(invalid.status_code, 400)
        page = client.get("/")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        common = {
            "csrf_token": csrf, "name": "Someone", "email": "user@example.test",
            "category": "error", "message": "Some problem occurred today."
        }
        for changes in (
            {"email": "fake"},
            {"category": "unsafe"},
            {"message": "short"},
            {"name": "x"},
        ):
            with self.subTest(changes=changes):
                answer = client.post("/contacto/enviar", data={**common, **changes})
                self.assertEqual(answer.status_code, 400)
        with self.app.app_context():
            total = self.db.session.execute(
                self.db.select(self.db.func.count(ContactMessage.id))
            ).scalar_one()
        # Test the honeypot from a different IP: invalid attempts also use the spam limit.
        client.environ_base["REMOTE_ADDR"] = "203.0.113.201"
        response = client.post("/contacto/enviar", data={**common, "website": "bot.example"})
        self.assertEqual(response.status_code, 303)
        with self.app.app_context():
            self.assertEqual(
                self.db.session.execute(
                    self.db.select(self.db.func.count(ContactMessage.id))
                ).scalar_one(), total
            )

        client2 = self.app.test_client()
        client2.environ_base["REMOTE_ADDR"] = "203.0.113.199"
        second_page = client2.get("/?lang=en")
        self.assertIn(b"Send us a message", second_page.data)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', second_page.data).group(1).decode()
        payload = {
            "csrf_token": token, "name": "<script>alert(1)</script>",
            "email": "escape@example.test", "category": "consulta",
            "message": "<img src=x onerror=alert(1)> A test report with HTML."
        }
        self.assertEqual(client2.post("/contacto/enviar", data=payload).status_code, 303)
        admin = self._signed_in_client("Admin")
        inbox = admin.get("/admin/contact-messages?status=all")
        self.assertIn(b"&lt;script&gt;", inbox.data)
        self.assertNotIn(b"<script>alert(1)</script>", inbox.data)
        self.assertIn(b"&lt;img", inbox.data)
        self.assertNotIn(b"<img src=x onerror=", inbox.data)

    def test_public_contact_optional_admin_email_and_failure_fallback(self):
        """Configured SMTP sends a copy; mail errors never erase the stored report."""
        from unittest.mock import patch
        from app.models.contact_message_model import ContactMessage

        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "203.0.113.202"
        token = re.search(
            rb'name="csrf_token" value="([^"]+)"', client.get("/").data
        ).group(1).decode()
        data = {
            "csrf_token": token, "name": "Correo Test",
            "email": "correo@example.test", "category": "error",
            "message": "La pantalla del panel no se abre desde un móvil."
        }
        settings = {
            "MAIL_USERNAME": "uni@example.test",
            "MAIL_PASSWORD": "test-password-not-real",
            "CONTACT_NOTIFY_EMAIL": "inbox@example.test"
        }
        with patch.dict(self.app.config, settings):
            with patch("app.services.email_service.send_email", return_value=True) as sender:
                response = client.post("/contacto/enviar", data=data)
                self.assertEqual(response.status_code, 303)
                sender.assert_called_once()
                self.assertEqual(sender.call_args.args[0], "inbox@example.test")
                self.assertIn("Correo Test", sender.call_args.args[2])

            client.environ_base["REMOTE_ADDR"] = "203.0.113.203"
            with patch("app.services.email_service.send_email", side_effect=OSError("SMTP down")):
                response = client.post("/contacto/enviar", data={
                    **data, "email": "smtp-error@example.test"
                })
                self.assertEqual(response.status_code, 303)
        with self.app.app_context():
            contact = self.db.session.execute(
                self.db.select(ContactMessage).where(
                    ContactMessage.email == "smtp-error@example.test"
                )
            ).scalar_one()
            self.assertEqual(contact.status, "new")

    def test_public_contact_per_ip_rate_limit(self):
        """Repeated anonymous requests cannot flood administrators' inbox."""
        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "203.0.113.200"
        page = client.get("/")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        form = {
            "csrf_token": csrf, "name": "Rate limit test",
            "email": "limit@example.test", "category": "soporte",
            "message": "Request submitted as a legitimate rate-limit test."
        }
        for n in range(5):
            with self.subTest(submission=n):
                response = client.post("/contacto/enviar", data=form)
                self.assertEqual(response.status_code, 303)
        self.assertEqual(client.post("/contacto/enviar", data=form).status_code, 429)

    def test_photo_upload_service_rejects_spoofs_and_strips_metadata(self):
        """One verified converter serves every photo form and never trusts names."""
        from io import BytesIO
        from pathlib import Path
        from PIL import Image
        from werkzeug.datastructures import FileStorage
        from app.services.profile_photo_service import (
            MAX_UPLOAD_BYTES, save_profile_photo, delete_profile_photo
        )

        def photo(payload, filename):
            return FileStorage(stream=BytesIO(payload), filename=filename)

        with self.app.app_context():
            for name, payload in (
                ("script.jpg", b"<script>alert(1)</script>"),
                ("fake.png", b"not a real image"),
                ("empty.jpg", b""),
                ("executable.exe", b"MZnot-an-image"),
                ("too-large.jpg", b"A" * (MAX_UPLOAD_BYTES + 1)),
            ):
                with self.subTest(invalid=name):
                    with self.assertRaises(ValueError):
                        save_profile_photo(photo(payload, name), kind="test")

            source = Image.new("RGBA", (3000, 1600), (100, 40, 230, 128))
            raw = BytesIO()
            source.save(raw, format="PNG", pnginfo=None)
            stored_path = None
            try:
                stored_path = save_profile_photo(
                    photo(raw.getvalue(), "my_photo.png"), kind="test"
                )
                self.assertTrue(stored_path.startswith("private_uploads/profile_photos/test_"))
                self.assertTrue(stored_path.endswith(".jpg"))
                destination = Path(self.app.root_path).parent / stored_path
                self.assertTrue(destination.is_file())
                with Image.open(destination) as verified:
                    self.assertEqual(verified.format, "JPEG")
                    self.assertEqual(verified.mode, "RGB")
                    self.assertLessEqual(max(verified.size), 1024)
                    self.assertNotIn("exif", verified.info)
            finally:
                delete_profile_photo(stored_path)
            self.assertFalse(destination.exists())

            # A header with huge declared pixel dimensions must not get decoded.
            huge = bytearray(BytesIO(raw.getvalue()).getvalue())
            huge[16:20] = (9000).to_bytes(4, "big")
            with self.assertRaises(ValueError):
                save_profile_photo(photo(bytes(huge), "huge.png"), kind="test")

    def test_private_profile_photos_require_login_and_owner(self):
        """Private photos must never be accessible as anonymous static files."""
        from io import BytesIO
        from pathlib import Path
        from PIL import Image
        from werkzeug.datastructures import FileStorage
        from app.models.user_model import User
        from app.services.profile_photo_service import save_profile_photo, delete_profile_photo

        raw = BytesIO()
        Image.new("RGB", (96, 72), (25, 85, 140)).save(raw, format="PNG")
        saved_path = None
        student_previous = None
        legacy_path = None
        try:
            with self.app.app_context():
                student = self.db.session.execute(
                    self.db.select(User).where(User.username == "StudentA")
                ).scalar_one()
                student_previous = student.photo_path
                saved_path = save_profile_photo(
                    FileStorage(stream=BytesIO(raw.getvalue()), filename="private.png"),
                    kind="testowner",
                )
                student.photo_path = saved_path
                self.db.session.commit()
                assert not (Path(self.app.static_folder) / saved_path).exists()

            anonymous = self.app.test_client()
            self.assertIn(
                anonymous.get("/account/profile-photo").status_code, (302, 401)
            )
            self.assertEqual(
                anonymous.get("/static/uploads/profile_photos/something.jpg").status_code,
                403,
            )
            self.assertEqual(
                anonymous.get("/static/img/profiles/something.jpg").status_code,
                403,
            )
            self.assertEqual(anonymous.get("/static/img/unitrack_logo.png").status_code, 200)

            student_client = self._signed_in_client("StudentA")
            photo = student_client.get("/account/profile-photo")
            self.assertEqual(photo.status_code, 200)
            self.assertEqual(photo.mimetype, "image/jpeg")
            self.assertIn("no-store", photo.headers.get("Cache-Control", ""))
            self.assertEqual(photo.data[:3], b"\xff\xd8\xff")
            self.assertEqual(
                student_client.get("/static/uploads/profile_photos/something.jpg").status_code,
                403,
            )
            dashboard = student_client.get("/student/dashboard")
            self.assertIn(b'/account/profile-photo', dashboard.data)
            self.assertNotIn(saved_path.encode(), dashboard.data)

            another_user = self._signed_in_client("TeacherA")
            self.assertEqual(another_user.get("/account/profile-photo").status_code, 404)

            # A profile photo migrated from a legacy public folder still works
            # through the signed-in user's private route, not a public URL.
            legacy_path = "uploads/profile_photos/unitrack-test-legacy-photo.jpg"
            legacy_file = Path(self.app.static_folder) / legacy_path
            legacy_file.parent.mkdir(parents=True, exist_ok=True)
            legacy_file.write_bytes(raw.getvalue())
            with self.app.app_context():
                student = self.db.session.execute(
                    self.db.select(User).where(User.username == "StudentA")
                ).scalar_one()
                student.photo_path = legacy_path
                self.db.session.commit()
            self.assertEqual(student_client.get("/account/profile-photo").status_code, 200)
            self.assertEqual(
                anonymous.get("/static/" + legacy_path).status_code, 403
            )
        finally:
            with self.app.app_context():
                student = self.db.session.execute(
                    self.db.select(User).where(User.username == "StudentA")
                ).scalar_one()
                student.photo_path = student_previous
                self.db.session.commit()
                delete_profile_photo(saved_path)
            if legacy_path:
                (Path(self.app.static_folder) / legacy_path).unlink(missing_ok=True)

    def test_all_role_photo_forms_reject_disguised_files_without_changing_account(self):
        """Admin, student, professor and staff must reject non-image uploads."""
        from io import BytesIO
        from app.models.user_model import User
        for username, settings_url, upload_url, upload_field in (
            ("Admin", "/admin/configuration", "/admin/configuration", "profile_image"),
            ("StudentA", "/student/configuration", "/student/configuration/photo", "photo"),
            ("TeacherA", "/professor/configuration", "/professor/configuration/update-photo", "photo"),
            ("StaffA", "/personal/configuration", "/personal/configuration/update-photo", "photo"),
        ):
            with self.subTest(role=username):
                client = self._signed_in_client(username)
                config = client.get(settings_url)
                self.assertEqual(config.status_code, 200)
                token_match = re.search(rb'name="csrf_token" value="([^"]+)"', config.data)
                self.assertIsNotNone(token_match)
                with self.app.app_context():
                    account = self.db.session.execute(self.db.select(User).where(
                        User.username == username
                    )).scalar_one()
                    prior_path = account.photo_path
                    details = {
                        "first_name": account.first_name,
                        "last_name": account.last_name,
                        "email": account.email,
                        "phone": account.phone,
                        "language": "es",
                    }
                details["csrf_token"] = token_match.group(1).decode("utf-8")
                details[upload_field] = (BytesIO(b"<html>not-an-image</html>"), "profile.jpg")
                posted = client.post(upload_url, data=details,
                                     content_type="multipart/form-data")
                self.assertIn(posted.status_code, (302, 303))
                with self.app.app_context():
                    account = self.db.session.execute(self.db.select(User).where(
                        User.username == username
                    )).scalar_one()
                    self.assertEqual(account.photo_path, prior_path)

    def test_public_landing_preserves_existing_login_and_registration(self):
        """The new homepage is public; existing auth forms remain unchanged."""
        client = self.app.test_client()
        landing = client.get("/")
        self.assertEqual(landing.status_code, 200)
        self.assertIn(b'lang="es"', landing.data)
        self.assertIn(b"UniTrack", landing.data)
        self.assertIn(b"ProTrack MX", landing.data)
        self.assertIn("Peyman Miyandashti".encode("utf-8"), landing.data)
        self.assertIn(b'img/upbc-campus-enhanced.jpg', landing.data)
        self.assertIn(b'img/protrack-mx-brand.svg', landing.data)
        self.assertIn(b'href="/auth/login-page"', landing.data)
        self.assertIn(b'href="/auth/register-page"', landing.data)
        self.assertIn(b'id="como-funciona"', landing.data)
        self.assertIn(b'id="beneficios"', landing.data)
        self.assertIn(b'id="proyectos"', landing.data)
        self.assertIn(b'id="caracteristicas"', landing.data)
        self.assertIn("Proyecto independiente".encode("utf-8"), landing.data)

        # ProTrack-style header is a single aligned grid on wide screens,
        # switching to a dropdown menu BEFORE buttons collide on smaller ones.
        self.assertIn(b"background:linear-gradient(90deg,#740018,#8a0021 55%,#5f0017)", landing.data)
        self.assertIn(b".header-actions .button-ghost{color:#fff", landing.data)
        self.assertIn(b"grid-template-columns:minmax(270px,1fr) max-content minmax(460px,1fr)", landing.data)
        self.assertIn(b'class="brand-title">Uni', landing.data)
        self.assertIn(b'class="nav-links" id="mainNav"', landing.data)
        self.assertIn(b"justify-self:end;gap:12px;min-width:max-content", landing.data)
        self.assertIn(b"min-height:690px", landing.data)
        self.assertIn(b"@media(max-width:1680px)", landing.data)
        self.assertIn(b"@media(max-width:1180px)", landing.data)
        self.assertIn(b"@media(max-width:1020px)", landing.data)
        self.assertIn(b'grid-template-areas:"brand actions" "nav nav"', landing.data)
        self.assertIn(b'grid-template-areas:"brand" "actions"', landing.data)
        self.assertIn(b"@media(max-width:920px)", landing.data)
        self.assertIn(b"@media(max-width:760px)", landing.data)
        self.assertIn(b"@media(max-width:650px)", landing.data)
        self.assertIn(b"@media(max-width:430px)", landing.data)
        self.assertIn(b"top:100%;left:0;right:0", landing.data)
        # Both header auth buttons use the same visual class, but retain
        # separate sign-in and registration destinations.
        self.assertIn(
            b'class="button button-ghost" href="/auth/login-page"', landing.data
        )
        self.assertIn(
            b'class="button button-ghost" href="/auth/register-page"', landing.data
        )

        english = client.get("/?lang=en")
        self.assertEqual(english.status_code, 200)
        self.assertIn(b'lang="en"', english.data)
        self.assertIn(b"How does UniTrack work?", english.data)
        spanish = client.get("/?lang=es")
        self.assertIn("¿Cómo funciona UniTrack?".encode("utf-8"), spanish.data)

        # The actual ProTrack brand file exists and loads locally.
        logo = client.get("/static/img/protrack-mx-brand.svg")
        self.assertEqual(logo.status_code, 200)
        self.assertIn(b"data:image/png;base64,", logo.data)

        login = client.get("/auth/login-page")
        register = client.get("/auth/register-page")
        self.assertEqual(login.status_code, 200)
        self.assertEqual(register.status_code, 200)
        self.assertIn(b'name="login"', login.data)
        self.assertIn(b'name="password"', login.data)
        self.assertIn(b'name="csrf_token"', login.data)
        self.assertIn(b'class="back-home-link"', login.data)
        self.assertIn(b'href="/"', login.data)
        spanish_login = client.get("/auth/login-page?language=es")
        self.assertIn("Volver al inicio".encode("utf-8"), spanish_login.data)
        self.assertIn(b'name="csrf_token"', register.data)

    def test_public_landing_feature_cards_link_to_explanations_and_logo_goes_top(self):
        """All five feature cards and every top-nav link resolve to actual sections."""
        client = self.app.test_client()
        for language in ("es", "en"):
            with self.subTest(language=language):
                response = client.get("/?lang=" + language)
                self.assertEqual(response.status_code, 200)
                html = response.data.decode("utf-8")
                for slug in ("credencial", "qr", "avisos", "historial", "seguridad", "soporte"):
                    target = "detalle-" + slug
                    self.assertIn('class="mini-feature" href="#' + target + '"', html)
                    self.assertIn('class="feature-detail" id="' + target + '"', html)
                self.assertEqual(html.count('class="mini-feature" href="#detalle-'), 6)
                self.assertEqual(html.count('class="feature-detail" id="detalle-'), 6)

                nav = re.search(r'<nav class="nav-links" id="mainNav".*?</nav>', html, re.S)
                self.assertIsNotNone(nav)
                destinations = re.findall(r'href="#([^"]+)"', nav.group())
                self.assertEqual(destinations, [
                    "inicio", "caracteristicas", "beneficios",
                    "como-funciona", "proyectos", "contacto"
                ])
                for section_id in destinations:
                    self.assertIn('id="' + section_id + '"', html)

                self.assertIn('class="brand" href="#inicio" data-return-top', html)
                self.assertIn('href="#inicio" class="nav-home" data-return-top', html)
                self.assertIn('window.scrollTo(0,0);', html)
                self.assertIn('root.style.scrollBehavior="auto"', html)
                self.assertIn('--landing-nav-offset', html)
                self.assertIn('class="menu-button" id="navToggle"', html)
                # Keep burgundy brand and existing auth links unchanged.
                self.assertIn('.site-header{background:linear-gradient(90deg,#740018,#8a0021 55%,#5f0017)', html)
                self.assertIn('href="/auth/login-page"', html)
                self.assertIn('href="/auth/register-page"', html)

    def test_public_homepage_reflects_current_qr_campus_access_features(self):
        """Homepage accurately describes current features without legacy attendance claims."""
        for lang in ("es", "en"):
            response = self.app.test_client().get("/?lang=" + lang)
            self.assertEqual(response.status_code, 200)
            body = response.data.decode("utf-8")
            self.assertIn("UniTrack", body)
            self.assertIn('href="/auth/login-page"', body)
            self.assertIn('href="/auth/register-page"', body)
            self.assertIn('name="csrf_token"', body)
            self.assertIn('id="contact_category"', body)
            self.assertIn('id="detalle-soporte"', body)
            self.assertIn('id="detalle-seguridad"', body)
            self.assertNotIn("Academic management project bringing together", body)
            self.assertNotIn("Clases, asistencia y acceso", body)
            if lang == "es":
                for phrase in (
                    "QR permanente y credencial institucional",
                    "Permisos y pases temporales",
                    "Reportar, responder y cerrar conversaciones",
                    "Historial de entradas y salidas",
                    "Centro de notificaciones",
                    "Proyecto independiente",
                ):
                    self.assertIn(phrase, body)
            else:
                for phrase in (
                    "Permanent QR and university ID card",
                    "Permissions and temporary passes",
                    "Report, reply and close conversations",
                    "Entry and exit history",
                    "Notification center",
                    "Independent project",
                ):
                    self.assertIn(phrase, body)

    def test_login_username_case_insensitive(self):
        from app.services.user_service import get_user_by_username
        with self.app.app_context():
            for typed in ("Admin", "admin", "ADMIN", "aDmIn"):
                self.assertEqual(get_user_by_username(typed).username, "Admin")

    def test_public_homepage_all_roles_and_updated_campus_mission(self):
        """Five roles, current QR product, accessible mobile layout and public contact."""
        for lang in ("es", "en"):
            response = self.app.test_client().get("/?lang=" + lang)
            self.assertEqual(response.status_code, 200)
            html = response.data.decode("utf-8")
            self.assertIn('data-homepage-version="qr-access-2026-11"', html)
            self.assertIn('id="contenido-principal"', html)
            self.assertIn('class="skip-link" href="#contenido-principal"', html)
            self.assertEqual(html.count('class="role-item"'), 5)
            self.assertIn('id="detalle-credencial"', html)
            self.assertNotIn('id="detalle-gestion"', html)
            self.assertNotIn("Clases, asistencia y acceso", html)
            self.assertNotIn("Gestión académica</h3>", html)
            self.assertNotIn("Academic management</h3>", html)
            self.assertNotIn("www.elimparcial.com/resizer/v2/", html)
            self.assertIn("upbc-campus-enhanced.jpg", html)
            self.assertIn("role-panel{display:grid", html)
            self.assertIn('class="contact-form" method="POST"', html)
            self.assertIn('name="csrf_token"', html)
            expected = (
                ("Visitantes", "Pases temporales autorizados",
                 "Identidad digital y control de acceso",
                 "UniTrack se enfoca en el acceso al campus",
                 "Fuera del periodo autorizado",
                 "El reemplazo de QR requiere aprobación")
                if lang == "es" else
                ("Visitors", "Authorized temporary passes",
                 "Digital credentials and campus access control",
                 "UniTrack focuses on campus access",
                 "Outside its authorized period",
                 "QR replacement requires approval")
            )
            for text in expected:
                self.assertIn(text, html)

    def test_public_mobile_get_does_not_check_in(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_scan_token
        with self.app.app_context():
            user = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            token = issue_scan_token(user)
            count_before = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
            ).scalar_one()
        response = self.app.test_client().get("/student/access-control/mobile-scan", query_string={"scan_token": token})
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            count_after = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
            ).scalar_one()
            self.assertEqual(count_before, count_after)

    def test_signed_qr_is_one_use(self):
        from app.models.user_model import User
        from app.services.scan_token_service import issue_scan_token, resolve_scan_token, consume_scan_token
        with self.app.app_context():
            user = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            token = issue_scan_token(user)
            resolved, record = resolve_scan_token(token)
            self.assertEqual(resolved.id, user.id)
            consume_scan_token(record)
            with self.assertRaises(ValueError):
                resolve_scan_token(token)

    def test_same_professor_qr_checkin_then_checkout_and_history(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.models.access_scan_pair_model import AccessScanPair
        from app.services.scan_token_service import issue_access_credential
        with self.app.app_context():
            professor = self.db.session.execute(
                self.db.select(User).where(User.username == "TeacherA")
            ).scalar_one()
            signed_qr, backup = issue_access_credential(professor)
            professor_id = professor.id

        admin = self._signed_in_client("Admin")
        page = admin.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        form = {"csrf_token": csrf.group(1).decode("utf-8"), "qr_text": signed_qr}

        first = admin.post("/admin/access-control", data=form)
        self.assertEqual(first.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), first.data)
        with self.app.app_context():
            logs = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == professor_id
            )).scalars().all()
            self.assertEqual(len(logs), 1)
            self.assertIsNone(logs[0].check_out_time)
            pair = self.db.session.execute(self.db.select(AccessScanPair).where(
                AccessScanPair.access_log_id == logs[0].id
            )).scalar_one()
            pair.checked_in_at -= timedelta(seconds=30)
            self.db.session.commit()

        second = admin.post("/admin/access-control", data=form)
        self.assertEqual(second.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), second.data)
        self.assertIn("Salida".encode("utf-8"), second.data)
        with self.app.app_context():
            logs = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == professor_id
            )).scalars().all()
            self.assertEqual(len(logs), 1)
            self.assertIsNotNone(logs[0].check_out_time)
            self.assertEqual(logs[0].access_status, "checked_out")
            self.assertGreaterEqual(logs[0].check_out_time, logs[0].check_in_time)
            pair = self.db.session.execute(self.db.select(AccessScanPair).where(
                AccessScanPair.access_log_id == logs[0].id
            )).scalar_one()
            self.assertIsNotNone(pair.checked_out_at)

        professor_client = self._signed_in_client("TeacherA")
        history = professor_client.get("/professor/access-control")
        self.assertEqual(history.status_code, 200)
        self.assertIn("Fuera del campus".encode("utf-8"), history.data)
        # History row shows both entry and exit, not just an open check-in.
        self.assertIn(logs[0].check_out_time.strftime("%I:%M %p").encode(), history.data)

        third = admin.post("/admin/access-control", data=form)
        self.assertEqual(third.status_code, 200)
        self.assertIn("Escaneo rechazado".encode("utf-8"), third.data)
        with self.app.app_context():
            count = self.db.session.execute(self.db.select(self.db.func.count(AccessLog.id)).where(
                AccessLog.student_id == professor_id
            )).scalar_one()
            self.assertEqual(count, 1)

    def test_new_qr_closes_preexisting_open_entry_without_deleting_history(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_access_credential
        from app.services.access_log_service import create_check_in
        with self.app.app_context():
            person = self.db.session.execute(
                self.db.select(User).where(User.username == "StaffA")
            ).scalar_one()
            old = create_check_in(student_id=person.id, access_method="qr",
                                  notes="Earlier campus entry")
            original_id = old.id
            user_id = person.id
            new_qr, _ = issue_access_credential(person)
        admin = self._signed_in_client("Admin")
        page = admin.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        response = admin.post("/admin/access-control", data={
            "csrf_token": csrf.group(1).decode("utf-8"),
            "qr_text": new_qr,
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), response.data)
        with self.app.app_context():
            logs = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == user_id
            )).scalars().all()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].id, original_id)
            self.assertIsNotNone(logs[0].check_out_time)
            self.assertEqual(logs[0].access_status, "checked_out")

    def test_same_qr_checkout_remains_valid_after_initial_five_minutes(self):
        from app.models.user_model import User
        from app.models.scan_token_model import ScanToken
        from app.models.access_scan_pair_model import AccessScanPair
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_access_credential
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            person = User(
                username="LongSessionMember", email="long-session@example.test",
                first_name="Long", last_name="Session", phone="0000000000",
                role="estudiante", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"),
            )
            self.db.session.add(person)
            self.db.session.commit()
            qr, _ = issue_access_credential(person)
            user_id = person.id
        admin = self._signed_in_client("Admin")
        page = admin.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        payload = {
            "csrf_token": csrf.group(1).decode("utf-8"),
            "qr_text": qr,
        }
        first = admin.post("/admin/access-control", data=payload)
        self.assertIn("Escaneo correcto".encode("utf-8"), first.data)
        with self.app.app_context():
            pair = self.db.session.execute(
                self.db.select(AccessScanPair).where(
                    AccessScanPair.user_id == user_id
                ).order_by(AccessScanPair.id.desc())
            ).scalars().first()
            self.assertIsNotNone(pair)
            pair.checked_in_at = datetime.utcnow() - timedelta(hours=2)
            credential = self.db.session.get(ScanToken, pair.scan_token_id)
            credential.expires_at = datetime.utcnow() - timedelta(hours=1)
            self.db.session.commit()
        second = admin.post("/admin/access-control", data=payload)
        self.assertIn("Escaneo correcto".encode("utf-8"), second.data)
        with self.app.app_context():
            log = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == user_id
            ).order_by(AccessLog.id.desc())).scalars().first()
            self.assertIsNotNone(log.check_out_time)

    def test_professor_history_live_without_new_qr_generation(self):
        from app.models.user_model import User
        from app.models.access_scan_pair_model import AccessScanPair
        from app.models.scan_token_model import ScanToken
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_access_credential
        with self.app.app_context():
            user = User(
                username="LiveHistoryTeacher", email="live-history-teacher@example.test",
                first_name="Live", last_name="History", role="docente",
                phone="0000000000", language="es", is_active_user=True,
                password_hash="not-used-in-this-test",
            )
            self.db.session.add(user)
            self.db.session.commit()
            qr, _ = issue_access_credential(user)
            user_id = user.id

        # Read-only endpoint is protected even when guessed by an outsider.
        public = self.app.test_client().get("/api/access-control/live")
        self.assertNotEqual(public.status_code, 200)

        admin = self._signed_in_client("Admin")
        page = admin.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        form = {"csrf_token": csrf.group(1).decode(), "qr_text": qr}
        first = admin.post("/admin/access-control", data=form)
        self.assertIn("Escaneo correcto".encode(), first.data)
        with self.app.app_context():
            pair = self.db.session.execute(self.db.select(AccessScanPair).where(
                AccessScanPair.user_id == user_id
            )).scalar_one()
            pair.checked_in_at -= timedelta(seconds=20)
            before_tokens = self.db.session.execute(
                self.db.select(self.db.func.count(ScanToken.id)).where(ScanToken.user_id == user_id)
            ).scalar_one()
            self.db.session.commit()

        # Person can view their own status via the existing authenticated
        # endpoint without refreshing the page or minting a new QR.
        teacher = self.app.test_client()
        from app.utils.session_security import password_session_tag
        with self.app.app_context():
            professor = self.db.session.get(User, user_id)
            tag = password_session_tag(professor)
        with teacher.session_transaction() as session_state:
            session_state["_user_id"] = str(user_id)
            session_state["_fresh"] = True
            session_state["password_session_tag"] = tag
        before = teacher.get("/api/access-control/live")
        self.assertEqual(before.status_code, 200)
        self.assertEqual(before.get_json()["status"]["status"], "checked_in")
        self.assertEqual(before.get_json()["records"][0]["check_out"], "--")

        second = admin.post("/admin/access-control", data=form)
        self.assertIn("Escaneo correcto".encode(), second.data)
        after = teacher.get("/api/access-control/live")
        self.assertEqual(after.status_code, 200)
        self.assertEqual(after.get_json()["status"]["status"], "checked_out")
        self.assertNotEqual(after.get_json()["records"][0]["check_out"], "--")
        with self.app.app_context():
            after_tokens = self.db.session.execute(
                self.db.select(self.db.func.count(ScanToken.id)).where(ScanToken.user_id == user_id)
            ).scalar_one()
            self.assertEqual(before_tokens, after_tokens)

    def test_access_control_shared_admin_design_and_private_member_history(self):
        """All roles see the same QR components, while own history stays private."""
        admin = self._signed_in_client("Admin")
        self.assertIn(b'class="history-card"', admin.get("/admin/access-control").data)
        for username, route in (
            ("StudentA", "/student/access-control"),
            ("TeacherA", "/professor/access-control"),
            ("StaffA", "/personal/access-control"),
        ):
            with self.subTest(username=username):
                client = self._signed_in_client(username)
                response = client.get(route)
                self.assertEqual(response.status_code, 200)
                html = response.data.decode("utf-8")
                for marker in ('class="operator-qr-card"', 'id="operatorQrTitle"',
                               'id="operatorPassTitle"', 'id="operatorOwnQrTitle"',
                               'class="summary-card"', 'data-live-campus-history'):
                    self.assertIn(marker, html)
                self.assertIn('name="qr_text"', html)
                self.assertIn('name="pass_code"', html)
                self.assertNotIn('Ver historial completo', html)
                self.assertNotIn('class="history-card"', html)
                body = client.get("/api/access-control/live").get_json()
                self.assertTrue(all(e["username"] == username for e in body["events"]))

    def test_role_access_history_shows_each_event_with_counts(self):
        """All three role pages share the event-by-event design and own-user scope."""
        from app.models.user_model import User
        from app.services.access_log_service import create_check_in, create_check_out
        from werkzeug.security import generate_password_hash

        for username, role, prefix in (
            ("EventStudent", "estudiante", "/student"),
            ("EventTeacher", "docente", "/professor"),
            ("EventStaff", "personal", "/personal"),
        ):
            with self.app.app_context():
                account = User(
                    username=username,
                    email=username.lower() + "@example.test",
                    first_name=username, last_name="History",
                    role=role, language="es", phone="0000000000",
                    password_hash=generate_password_hash("TestingPassword123!"),
                    is_active_user=True,
                )
                self.db.session.add(account)
                self.db.session.commit()
                uid = account.id
                create_check_in(student_id=uid)
                create_check_out(student_id=uid)
                create_check_in(student_id=uid)

            with self.subTest(role=role):
                client = self._signed_in_client(username)
                page = client.get(prefix + "/access-control")
                self.assertEqual(page.status_code, 200)
                self.assertIn(b"data-live-campus-history", page.data)
                self.assertIn(b"data-access-count-in>2</strong>", page.data)
                self.assertIn(b"data-access-count-out>1</strong>", page.data)
                self.assertIn(b"data-access-count-total>3</strong>", page.data)
                self.assertEqual(page.data.count(b"<tr>"), page.data.count(b"</tr>"))
                self.assertIn("Historial de Acceso".encode("utf-8"), page.data)
                self.assertIn("Entrada".encode("utf-8"), page.data)
                self.assertIn("Salida".encode("utf-8"), page.data)

                live = client.get("/api/access-control/live")
                self.assertEqual(live.status_code, 200)
                body = live.get_json()
                self.assertEqual(body["event_counts"], {
                    "check_ins": 2, "check_outs": 1, "total": 3
                })
                self.assertEqual(len(body["events"]), 3)
                self.assertEqual(
                    [entry["action"] for entry in body["events"]],
                    ["check_in", "check_out", "check_in"],
                )
                self.assertEqual(
                    {entry["username"] for entry in body["events"]}, {username}
                )

                filtered = client.get(prefix + "/access-control", query_string={
                    "date": "01/01/2000"
                })
                self.assertEqual(filtered.status_code, 200)
                self.assertIn(b"data-access-count-total>0</strong>", filtered.data)
                self.assertIn(b'data-access-empty', filtered.data)

    def test_professor_student_staff_pages_have_live_history_widget(self):
        for username, path in (
            ("StudentA", "/student/access-control"),
            ("TeacherA", "/professor/access-control"),
            ("StaffA", "/personal/access-control"),
        ):
            with self.subTest(username=username):
                page = self._signed_in_client(username).get(path)
                self.assertEqual(page.status_code, 200)
                self.assertIn(b"data-live-campus-history", page.data)
                self.assertIn(b"js/access-history-live.js", page.data)
        script = self.app.test_client().get("/static/js/access-history-live.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn(b"/api/access-control/live", script.data)
        self.assertIn(b"replaceChildren", script.data)

    def test_immediate_duplicate_scan_never_checks_out(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_access_credential
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            student = User(
                username="DuplicateScanMember", email="duplicate-scan@example.test",
                first_name="Duplicate", last_name="Scan", phone="0000000000",
                role="estudiante", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"),
            )
            self.db.session.add(student)
            self.db.session.commit()
            signed_qr, _code = issue_access_credential(student)
            student_id = student.id
        client = self._signed_in_client("Admin")
        page = client.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        payload = {
            "csrf_token": csrf.group(1).decode("utf-8"),
            "qr_text": signed_qr,
        }
        first = client.post("/admin/access-control", data=payload)
        self.assertIn("Escaneo correcto".encode("utf-8"), first.data)
        second = client.post("/admin/access-control", data=payload)
        self.assertIn("Escaneo rechazado".encode("utf-8"), second.data)
        with self.app.app_context():
            latest = self.db.session.execute(
                self.db.select(AccessLog).where(AccessLog.student_id == student_id)
                .order_by(AccessLog.id.desc())
            ).scalars().first()
            self.assertIsNone(latest.check_out_time)

    def test_csrf_rejects_unprotected_form(self):
        response = self.app.test_client().post("/auth/login-page", data={
            "login": "Admin", "password": "TestingPassword123!"
        })
        self.assertEqual(response.status_code, 400)

    def _signed_in_client(self, username="Admin"):
        # Give each independent integration client a different TEST-NET source IP.
        # Do not disable or raise the application's real login rate limits.
        self.__class__._login_ip_counter = getattr(self.__class__, "_login_ip_counter", 0) + 1
        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = f"198.51.100.{self.__class__._login_ip_counter}"
        response = client.get("/auth/login-page")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(token)
        response = client.post("/auth/login-page", data={
            "login": username, "password": "TestingPassword123!",
            "csrf_token": token.group(1).decode("utf-8"),
            "language": "es",
        })
        self.assertIn(response.status_code, (302, 303))
        return client

    def test_qr_only_navigation_disables_academic_attendance(self):
        """Academic attendance is removed; QR access history stays available."""
        admin = self._signed_in_client()
        teacher = self._signed_in_client("TeacherA")
        student = self._signed_in_client("StudentA")
        self.assertEqual(teacher.get("/attendance/classes").status_code, 404)
        self.assertEqual(admin.get("/attendance/classes").status_code, 404)
        self.assertEqual(student.get("/attendance/classes").status_code, 404)
        self.assertNotIn(b"Clases y asistencia", teacher.get("/professor/dashboard").data)
        response = admin.get("/admin/attendance-history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Historial de Entradas y Salidas", response.data)
        self.assertNotIn(b"Asistencia acad", response.data)
        response = student.get("/student/attendance-history")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/student/access-control", response.headers["Location"])

    def test_administrator_pages_render(self):
        client = self._signed_in_client()
        for url in (
            "/admin/dashboard", "/admin/users", "/admin/validation-codes",
            "/admin/configuration", "/admin/attendance-history",
            "/admin/access-control/scanner",
        ):
            with self.subTest(url=url):
                response = client.get(url)
                self.assertEqual(response.status_code, 200, url)
                self.assertIn(b"UniTrack", response.data)

    def test_admin_sidebar_uses_professional_svg_icons(self):
        client = self._signed_in_client()
        response = client.get("/admin/dashboard")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertEqual(html.count('class="nav-icon" aria-hidden="true"'), 12)
        self.assertIn('class="nav-icon" aria-hidden="true"><svg', html)
        self.assertIn("nav-link.active .nav-icon", html)
        self.assertIn('class="logout-button"><svg', html)
        self.assertNotIn('<span class="nav-icon">#</span>', html)
        self.assertNotIn('<span class="nav-icon">⌂</span>', html)

    def test_admin_pages_show_section_titles_without_repeated_dashboard_heading(self):
        """Only Tablero uses the Administrator Dashboard heading."""
        admin = self._signed_in_client("Admin")
        for route, expected in (
            ("/admin/users", "Administración de Usuarios"),
            ("/admin/access-control", "Sistema de Control de Acceso"),
            ("/admin/configuration", "Configuración del Administrador"),
            ("/avisos", "Centro de Notificaciones"),
        ):
            with self.subTest(route=route):
                response = admin.get(route)
                self.assertEqual(response.status_code, 200)
                self.assertIn(expected.encode("utf-8"), response.data)
                self.assertNotIn(b"Administrador Tablero", response.data)
                self.assertNotIn(
                    b"Bienvenido a tu tablero de administrador de UniTrack",
                    response.data,
                )
        dashboard = admin.get("/admin/dashboard")
        self.assertIn(b"Tablero del Administrador", dashboard.data)

    def test_personal_id_cards_use_normal_role_dashboards_and_print_only_card(self):
        """ID views keep UPBC shell; printing hides dashboard chrome."""
        for username, sidebar_marker in (
            ("Admin", 'class="admin-sidebar"'),
            ("StudentA", 'class="sidebar"'),
            ("TeacherA", 'class="sidebar"'),
            ("StaffA", 'class="sidebar"'),
        ):
            with self.subTest(username=username):
                client = self._signed_in_client(username)
                response = client.get("/credentials/card")
                self.assertEqual(response.status_code, 200)
                page = response.data.decode("utf-8")
                self.assertIn("Mi Credencial", page)
                self.assertIn("Universidad Politécnica", page)
                self.assertIn(sidebar_marker, page)
                self.assertIn('class="id-card"', page)
                self.assertIn("window.print()", page)
                self.assertIn("body *{visibility:hidden!important}", page)
                self.assertNotIn("<!doctype html>\n<html lang=\"es\">\n<head>\n<meta", page)
        admin = self._signed_in_client("Admin")
        self.assertIn("Credenciales y Visitantes".encode("utf-8"),
                      admin.get("/credentials/manage").data)

    def test_account_headers_keep_user_name_on_shared_pages(self):
        """The professor name remains visible on dashboard, inbox, and ID card."""
        for username, expected_name, routes in (
            ("TeacherA", "Teacher", ("/professor/dashboard", "/avisos",
                                      "/credentials/card", "/professor/configuration")),
            ("StudentA", "Student", ("/student/dashboard", "/avisos",
                                      "/credentials/card")),
            ("StaffA", "Staff", ("/personal/dashboard", "/avisos",
                                  "/credentials/card")),
        ):
            client = self._signed_in_client(username)
            for route in routes:
                with self.subTest(role=username, path=route):
                    response = client.get(route)
                    self.assertEqual(response.status_code, 200)
                    self.assertIn(b'class="profile-name"', response.data)
                    self.assertIn(expected_name.encode(), response.data)

    def test_chat_polling_is_private_and_admin_can_delete_one_thread(self):
        """Live updates appear to both parties; deletion purges only its report."""
        from app.models.contact_message_model import ContactMessage
        from app.models.support_conversation_model import SupportChatMessage, SupportChatState
        from app.models.support_reply_model import SupportReply, SupportReportSender
        student = self._signed_in_client("StudentA")
        form = student.get("/credentials/report")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', form.data).group(1).decode()
        for subject in ("Live update private 1", "Live update private 2"):
            self.assertEqual(student.post("/credentials/report", data={
                "csrf_token": csrf, "category": "soporte",
                "subject": subject, "description": "Please help with this account issue.",
            }).status_code, 302)
        with self.app.app_context():
            first = self.db.session.execute(self.db.select(ContactMessage).where(
                ContactMessage.body.contains("Live update private 1")
            )).scalar_one()
            second = self.db.session.execute(self.db.select(ContactMessage).where(
                ContactMessage.body.contains("Live update private 2")
            )).scalar_one()
            first_id, second_id = first.id, second.id
        url = f"/credentials/messages/{first_id}/updates"
        other = self._signed_in_client("TeacherA")
        self.assertEqual(other.get(url).status_code, 403)
        admin = self._signed_in_client("Admin")
        before = admin.get(url)
        self.assertEqual(before.status_code, 200)
        self.assertIn("no-store", before.headers["Cache-Control"])
        self.assertEqual(len(before.get_json()["messages"]), 1)
        self.assertFalse(before.get_json()["closed"])
        admin_page = admin.get(f"/admin/contact-messages/{first_id}/chat")
        self.assertIn(b"data-chat-updates-url", admin_page.data)
        self.assertIn(b"Eliminar chat permanentemente", admin_page.data)
        admin_csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                               admin_page.data).group(1).decode()
        member_chat = student.get(f"/credentials/messages/{first_id}/chat")
        self.assertNotIn(b"Eliminar chat permanentemente", member_chat.data)
        member_csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                                member_chat.data).group(1).decode()
        self.assertEqual(student.post(f"/credentials/messages/{first_id}/chat", data={
            "csrf_token": member_csrf, "message": "Can you see this without refreshing?",
        }).status_code, 302)
        self.assertEqual(len(admin.get(url).get_json()["messages"]), 2)
        self.assertEqual(admin.get(url).get_json()["messages"][-1]["body"],
                         "Can you see this without refreshing?")
        self.assertEqual(admin.post(f"/admin/contact-messages/{first_id}/reply", data={
            "csrf_token": admin_csrf, "reply": "Yes, I can see it now.",
        }).status_code, 302)
        member_updates = student.get(url)
        self.assertEqual(len(member_updates.get_json()["messages"]), 3)
        self.assertEqual(member_updates.get_json()["messages"][-1]["body"],
                         "Yes, I can see it now.")
        self.assertEqual(admin.post(f"/admin/contact-messages/{first_id}/delete", data={
            "csrf_token": admin_csrf, "confirm_delete": "wrong",
        }).status_code, 302)
        with self.app.app_context():
            self.assertIsNotNone(self.db.session.get(ContactMessage, first_id))
        outsider = other.post(f"/admin/contact-messages/{first_id}/delete", data={
            "csrf_token": admin_csrf, "confirm_delete": "ELIMINAR",
        })
        self.assertIn(outsider.status_code, (302, 400, 403))
        with self.app.app_context():
            self.assertIsNotNone(self.db.session.get(ContactMessage, first_id))
        deleted = admin.post(f"/admin/contact-messages/{first_id}/delete", data={
            "csrf_token": admin_csrf, "confirm_delete": "ELIMINAR",
        })
        self.assertEqual(deleted.status_code, 302)
        with self.app.app_context():
            self.assertIsNone(self.db.session.get(ContactMessage, first_id))
            self.assertIsNone(self.db.session.get(SupportReportSender, first_id))
            self.assertIsNone(self.db.session.get(SupportChatState, first_id))
            for model in (SupportReply, SupportChatMessage):
                self.assertEqual(self.db.session.execute(self.db.select(
                    self.db.func.count(model.id)
                ).where(model.report_id == first_id)).scalar_one(), 0)
            self.assertIsNotNone(self.db.session.get(ContactMessage, second_id))
        self.assertEqual(student.get(url).status_code, 404)
        self.assertTrue(student.get(url).get_json()["deleted"])
        self.assertEqual(student.get(f"/credentials/messages/{first_id}/chat").status_code, 404)
        self.assertNotIn(f"/credentials/messages/{first_id}/chat".encode(),
                         student.get("/credentials/messages").data)

    def test_two_way_support_chat_can_only_be_closed_by_admin(self):
        """Reporter replies back; closing prevents further messages on either side."""
        from app.models.contact_message_model import ContactMessage
        from app.models.support_conversation_model import (
            SupportChatMessage, SupportChatState
        )
        student = self._signed_in_client("StudentA")
        page = student.get("/credentials/report")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        self.assertEqual(student.post("/credentials/report", data={
            "csrf_token": token, "category": "error",
            "subject": "Two way support conversation",
            "description": "I cannot access my QR scanner.",
        }).status_code, 302)
        with self.app.app_context():
            report = self.db.session.execute(self.db.select(ContactMessage).where(
                ContactMessage.body.contains("Two way support conversation")
            )).scalar_one()
            rid = report.id
        self.assertIn(f"/credentials/messages/{rid}/chat".encode(),
                      student.get("/credentials/messages").data)
        admin = self._signed_in_client("Admin")
        self.assertIn(f"/admin/contact-messages/{rid}/chat".encode(),
                      admin.get("/admin/contact-messages").data)
        admin_page = admin.get(f"/admin/contact-messages/{rid}/chat")
        self.assertIn(b"Cerrar chat", admin_page.data)
        admin_csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                               admin_page.data).group(1).decode()
        self.assertEqual(admin.post(f"/admin/contact-messages/{rid}/reply", data={
            "csrf_token": admin_csrf, "reply": "What happened on scanning?"
        }).status_code, 302)
        student_page = student.get(f"/credentials/messages/{rid}/chat")
        self.assertIn(b"What happened on scanning?", student_page.data)
        self.assertNotIn(b"Cerrar chat", student_page.data)
        student_csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                                 student_page.data).group(1).decode()
        self.assertEqual(student.post(f"/credentials/messages/{rid}/chat", data={
            "csrf_token": student_csrf, "message": "The scan showed an empty screen."
        }).status_code, 302)
        with self.app.app_context():
            row = self.db.session.execute(self.db.select(SupportChatMessage).where(
                SupportChatMessage.report_id == rid
            )).scalar_one()
            row_id = row.id
            self.assertIsNone(row.admin_read_at)
        admin_page = admin.get(f"/admin/contact-messages/{rid}/chat")
        self.assertIn(b"The scan showed an empty screen.", admin_page.data)
        with self.app.app_context():
            self.assertIsNotNone(self.db.session.get(SupportChatMessage, row_id).admin_read_at)
        other = self._signed_in_client("TeacherA")
        self.assertEqual(other.get(f"/credentials/messages/{rid}/chat").status_code, 403)
        self.assertIn(student.post(f"/admin/contact-messages/{rid}/close",
                                    data={"csrf_token": student_csrf}).status_code,
                      (302, 403))
        with self.app.app_context():
            self.assertIsNone(self.db.session.get(SupportChatState, rid))
        self.assertEqual(admin.post(f"/admin/contact-messages/{rid}/close", data={
            "csrf_token": admin_csrf
        }).status_code, 302)
        with self.app.app_context():
            self.assertIsNotNone(self.db.session.get(SupportChatState, rid).closed_at)
        closed_page = student.get(f"/credentials/messages/{rid}/chat")
        self.assertIn(b"Cerrado", closed_page.data)
        self.assertIn(b"The scan showed an empty screen.", closed_page.data)
        self.assertNotIn(b'name="message"', closed_page.data)
        self.assertEqual(student.post(f"/credentials/messages/{rid}/chat", data={
            "csrf_token": student_csrf, "message": "After closure"
        }).status_code, 409)
        self.assertEqual(admin.post(f"/admin/contact-messages/{rid}/reply", data={
            "csrf_token": admin_csrf, "reply": "After closure"
        }).status_code, 409)
        with self.app.app_context():
            self.assertEqual(self.db.session.execute(
                self.db.select(self.db.func.count(SupportChatMessage.id)).where(
                    SupportChatMessage.report_id == rid
                )
            ).scalar_one(), 1)

    def test_in_app_support_reply_badge_clears_only_after_read(self):
        """Admin reply count belongs to recipient, and is cleared on acknowledgement."""
        from app.models.contact_message_model import ContactMessage
        from app.models.support_reply_model import SupportReply, SupportReportSender
        from app.models.user_model import User

        student = self._signed_in_client("StudentA")
        form = student.get("/credentials/report")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', form.data).group(1).decode()
        self.assertEqual(student.post("/credentials/report", data={
            "csrf_token": csrf, "category": "soporte",
            "subject": "Unread badge support request",
            "description": "Please help me check my account credential.",
        }).status_code, 302)
        with self.app.app_context():
            report = self.db.session.execute(self.db.select(ContactMessage).where(
                ContactMessage.body.contains("Unread badge support request")
            )).scalar_one()
            rid = report.id
            self.assertIn("Asunto: Unread badge support request\n\n", report.body)
            owner = self.db.session.execute(self.db.select(User).where(
                User.username == "StudentA"
            )).scalar_one()
            self.assertEqual(self.db.session.get(SupportReportSender, rid).user_id, owner.id)
        admin = self._signed_in_client("Admin")
        inbox = admin.get("/admin/contact-messages?status=all")
        self.assertEqual(inbox.status_code, 200)
        self.assertIn(f"/admin/contact-messages/{rid}/chat".encode(), inbox.data)
        admin_csrf = re.search(rb'name="csrf_token" value="([^"]+)"', inbox.data).group(1).decode()
        self.assertEqual(admin.post(f"/admin/contact-messages/{rid}/reply", data={
            "csrf_token": admin_csrf, "reply": "Please try again; the credential is active.",
        }).status_code, 302)
        messages = student.get("/credentials/messages")
        self.assertIn(b"Please try again; the credential is active.", messages.data)
        self.assertIn(b"data-unread-messages", messages.data)
        with self.app.app_context():
            reply = self.db.session.execute(self.db.select(SupportReply).where(
                SupportReply.report_id == rid
            )).scalar_one()
            reply_id = reply.id
        read_csrf = re.search(rb'name="csrf_token" value="([^"]+)"', messages.data).group(1).decode()
        other = self._signed_in_client("TeacherA")
        self.assertNotEqual(other.post(f"/credentials/messages/{reply_id}/read",
                                       data={"csrf_token": read_csrf}).status_code, 302)
        self.assertEqual(student.post(f"/credentials/messages/{reply_id}/read",
                                      data={"csrf_token": read_csrf}).status_code, 302)
        with self.app.app_context():
            self.assertIsNotNone(self.db.session.get(SupportReply, reply_id).read_at)
        self.assertIn(b"Please try again; the credential is active.", student.get("/credentials/messages").data)

    def test_compact_report_link_and_header_alerts_for_each_role(self):
        from app.models.user_model import User
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            visitor = User(username="SupportBadgeVisitor", email="badge@example.test",
                first_name="Support", last_name="Visitor", phone="0000000000",
                role="visitante", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"))
            self.db.session.add(visitor)
            self.db.session.commit()
        for username, path in (("Admin", "/admin/dashboard"),
                               ("StudentA", "/student/dashboard"),
                               ("TeacherA", "/professor/dashboard"),
                               ("StaffA", "/personal/dashboard"),
                               ("SupportBadgeVisitor", "/credentials/visitor")):
            with self.subTest(username=username):
                page = self._signed_in_client(username).get(path)
                self.assertEqual(page.status_code, 200)
                self.assertIn(b'uni-account-alerts', page.data)
                self.assertIn(b'aria-label="Mensajes', page.data)
                self.assertIn(b'aria-label="Notificaciones', page.data)
                self.assertIn(b'href="/credentials/report"', page.data)
                self.assertIn(b"Reportar", page.data)

    def test_signed_in_users_can_report_issues_to_private_admin_inbox(self):
        from app.models.contact_message_model import ContactMessage
        from app.models.user_model import User
        from werkzeug.security import generate_password_hash

        with self.app.app_context():
            visitor = User(
                username="SupportVisitor", email="supportvisitor@example.test",
                first_name="Support", last_name="Visitor", phone="0000000000",
                role="visitante", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"),
            )
            self.db.session.add(visitor)
            self.db.session.commit()
        submitted = []
        for username in ("Admin", "StudentA", "TeacherA", "StaffA", "SupportVisitor"):
            client = self._signed_in_client(username)
            page = client.get("/credentials/report")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Reportar un problema", page.data)
            csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
            self.assertIsNotNone(csrf)
            response = client.post("/credentials/report", data={
                "category": "error", "subject": "Issue from " + username,
                "description": "The scanner did not work for my account.",
                "csrf_token": csrf.group(1).decode(),
            })
            self.assertEqual(response.status_code, 302)
            submitted.append(username)
        with self.app.app_context():
            messages = self.db.session.execute(
                self.db.select(ContactMessage).where(
                    ContactMessage.category == "error",
                    ContactMessage.body.contains("Issue from "),
                )
            ).scalars().all()
            self.assertEqual(len(messages), 5)
            for username in submitted:
                self.assertTrue(any(
                    "@" + username in item.body and "Issue from " + username in item.body
                    for item in messages
                ))
        admin = self._signed_in_client("Admin")
        inbox = admin.get("/admin/contact-messages?status=all")
        self.assertEqual(inbox.status_code, 200)
        self.assertIn(b"Issue from TeacherA", inbox.data)
        self.assertIn(b"Issue from SupportVisitor", inbox.data)
        student = self._signed_in_client("StudentA")
        self.assertNotEqual(student.get("/admin/contact-messages").status_code, 200)

    def test_qr_replacement_request_review_and_history_stay_in_credentials(self):
        """Users request, admin approves, both sides retain approval history."""
        from app.models.user_model import User
        from app.models.permanent_credential_model import CredentialReplacementRequest
        from app.services.permanent_credential_service import (
            permanent_credential_for_user, resolve_permanent_credential
        )
        from app.models.admin_audit_model import AdminAuditLog
        from werkzeug.security import generate_password_hash

        with self.app.app_context():
            person = User(
                username="QRInboxRequester", email="qr-inbox-requester@example.test",
                first_name="Inbox", last_name="Requester", role="estudiante",
                phone="0000000000", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"),
            )
            self.db.session.add(person)
            self.db.session.commit()
            uid = person.id
            previous_qr, _ = permanent_credential_for_user(person)

        student = self._signed_in_client("QRInboxRequester")
        card = student.get("/credentials/card")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', card.data).group(1).decode()
        sent = student.post("/credentials/request-replacement", data={
            "reason": "Extravié mi credencial QR impresa.",
            "csrf_token": csrf,
        })
        self.assertEqual(sent.status_code, 302)
        self.assertIn(b"Pendiente de aprobaci", student.get("/credentials/card").data)

        admin = self._signed_in_client("Admin")
        inbox = admin.get("/admin/contact-messages")
        self.assertEqual(inbox.status_code, 200)
        self.assertNotIn(b"QRInboxRequester", inbox.data)
        management = admin.get("/credentials/manage")
        self.assertEqual(management.status_code, 200)
        self.assertIn(b"QRInboxRequester", management.data)
        self.assertIn(b"Extravi", management.data)
        self.assertIn(b"Aprobar y reemplazar", management.data)
        self.assertIn(b"Historial de solicitudes de cambio de QR", management.data)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', management.data).group(1).decode()

        with self.app.app_context():
            item = self.db.session.execute(
                self.db.select(CredentialReplacementRequest).where(
                    CredentialReplacementRequest.user_id == uid
                )
            ).scalar_one()
            request_id = item.id
            self.assertEqual(item.status, "pending")
            self.assertEqual(resolve_permanent_credential(previous_qr)[0].id, uid)

        # An unrelated account can neither view the admin queue nor approve.
        other = self._signed_in_client("StudentA")
        self.assertEqual(other.get("/admin/contact-messages").status_code, 302)
        other_post = other.post(
            f"/credentials/replacement/{request_id}/review",
            data={"decision": "approve", "csrf_token": csrf},
        )
        self.assertIn(other_post.status_code, (302, 403, 400))
        with self.app.app_context():
            self.assertEqual(
                self.db.session.get(CredentialReplacementRequest, request_id).status,
                "pending",
            )

        approved = admin.post(
            f"/credentials/replacement/{request_id}/review",
            data={"decision": "approve", "csrf_token": token},
        )
        self.assertEqual(approved.status_code, 302)
        self.assertIn("/credentials/manage", approved.headers["Location"])
        with self.app.app_context():
            reviewed = self.db.session.get(CredentialReplacementRequest, request_id)
            self.assertEqual(reviewed.status, "approved")
            self.assertIsNotNone(reviewed.reviewed_at)
            admin_account = self.db.session.execute(
                self.db.select(User).where(User.username == "Admin")
            ).scalar_one()
            self.assertEqual(reviewed.reviewed_by, admin_account.id)
            with self.assertRaises(ValueError):
                resolve_permanent_credential(previous_qr)
            new_qr, _ = permanent_credential_for_user(self.db.session.get(User, uid))
            self.assertNotEqual(new_qr, previous_qr)
            self.assertEqual(resolve_permanent_credential(new_qr)[0].id, uid)
            audit = self.db.session.execute(
                self.db.select(AdminAuditLog).where(
                    AdminAuditLog.action == "qr_replacement_approved",
                    AdminAuditLog.target_user_id == uid,
                )
            ).scalars().first()
            self.assertIsNotNone(audit)

        updated_management = admin.get("/credentials/manage")
        self.assertIn(b"QRInboxRequester", updated_management.data)
        self.assertIn(b"Aprobada", updated_management.data)
        self.assertIn(b"Revisado por", updated_management.data)
        self.assertIn(b"Admin", updated_management.data)
        self.assertIn(b"Fecha de revisi", updated_management.data)
        self.assertNotIn(b"QRInboxRequester", admin.get("/admin/contact-messages").data)
        self.assertIn(b"Aprobada", student.get("/credentials/card").data)

    def test_permanent_cards_and_approved_qr_rotation(self):
        """A registered user's printed QR is stable until admin-approved replacement."""
        from werkzeug.security import generate_password_hash
        from app.models.user_model import User
        from app.services.permanent_credential_service import (
            permanent_credential_for_user, resolve_permanent_credential,
            request_replacement, review_replacement,
        )
        from app.models.permanent_credential_model import CredentialReplacementRequest

        with self.app.app_context():
            person = User(
                username="PermanentCardMember", email="permanent-card@example.test",
                first_name="Permanent", last_name="Card", phone="0000000000",
                role="estudiante", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"),
            )
            self.db.session.add(person)
            self.db.session.commit()
            uid = person.id
            token, code = permanent_credential_for_user(person)
            self.assertEqual((token, code), permanent_credential_for_user(person))
            self.assertEqual(resolve_permanent_credential(token)[0].id, uid)
            self.assertEqual(resolve_permanent_credential(code)[0].id, uid)
            self.assertEqual(resolve_permanent_credential("EST-" + code[4:])[0].id, uid)
        owner = self._signed_in_client("PermanentCardMember")
        card = owner.get("/credentials/card")
        self.assertEqual(card.status_code, 200)
        self.assertIn(b"Imprimir / Guardar como PDF", card.data)
        self.assertIn(b"data:image/png;base64,", card.data)
        self.assertEqual(card.data, owner.get("/credentials/card").data)
        other = self._signed_in_client("StudentA")
        self.assertEqual(other.get(f"/credentials/card/{uid}").status_code, 403)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', card.data).group(1).decode()
        requested = owner.post("/credentials/request-replacement", data={
            "csrf_token": csrf, "reason": "Extravié mi credencial impresa.",
        })
        self.assertEqual(requested.status_code, 302)
        with self.app.app_context():
            item = self.db.session.execute(self.db.select(CredentialReplacementRequest).where(
                CredentialReplacementRequest.user_id == uid
            )).scalar_one()
            admin = self.db.session.execute(self.db.select(User).where(
                User.username == "Admin"
            )).scalar_one()
            review_replacement(item.id, admin, True)
            updated = self.db.session.get(User, uid)
            new_token, new_code = permanent_credential_for_user(updated)
            self.assertNotEqual(token, new_token)
            self.assertNotEqual(code, new_code)
            with self.assertRaises(ValueError):
                resolve_permanent_credential(token)
            with self.assertRaises(ValueError):
                resolve_permanent_credential(code)
            self.assertEqual(resolve_permanent_credential(new_token)[0].id, uid)
        administrator = self._signed_in_client("Admin")
        self.assertEqual(administrator.get(f"/credentials/card/{uid}").status_code, 200)
        self.assertEqual(administrator.get("/credentials/manage").status_code, 200)

    def test_permanent_qr_reuses_same_code_for_multiple_visits(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.permanent_credential_service import permanent_credential_for_user
        from app.utils.local_time import campus_now
        with self.app.app_context():
            person = User(username="RepeatPermanentMember", email="repeat-permanent@example.test",
                first_name="Repeat", last_name="Member", phone="0000000000", role="docente",
                language="es", is_active_user=True, password_hash="not-used-in-this-test")
            self.db.session.add(person)
            self.db.session.commit()
            uid = person.id
            token, code = permanent_credential_for_user(person)
        client = self._signed_in_client("Admin")
        page = client.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        form = {"csrf_token": csrf, "qr_text": token}
        first = client.post("/admin/access-control", data=form)
        self.assertIn("Escaneo correcto".encode("utf-8"), first.data)
        fast = client.post("/admin/access-control", data={"csrf_token": csrf, "pass_code": code})
        self.assertIn("Escaneo rechazado".encode("utf-8"), fast.data)
        with self.app.app_context():
            open_log = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == uid, AccessLog.check_out_time.is_(None)
            )).scalar_one()
            open_log.check_in_time = campus_now() - timedelta(seconds=10)
            self.db.session.commit()
        second = client.post("/admin/access-control", data={"csrf_token": csrf, "pass_code": code})
        self.assertIn("Escaneo correcto".encode("utf-8"), second.data)
        with self.app.app_context():
            previous = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == uid
            )).scalar_one()
            self.assertIsNotNone(previous.check_out_time)
            previous.check_out_time = campus_now() - timedelta(seconds=10)
            self.db.session.commit()
        third = client.post("/admin/access-control", data=form)
        self.assertIn("Escaneo correcto".encode("utf-8"), third.data)
        with self.app.app_context():
            logs = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == uid
            )).scalars().all()
            self.assertEqual(len(logs), 2)

    def test_visitor_movements_appear_in_unified_admin_campus_history(self):
        """Guest check-in/out is visible in the SAME table and counters as members."""
        from app.models.user_model import User
        from app.models.visitor_access_model import VisitorAccessLog
        from app.services.visitor_access_service import issue_visitor_pass, visitor_token
        from app.routes.admin_views import build_global_access_records, count_access_events
        from app.utils.local_time import campus_now

        name = "GuestHistoryDisplayPF08"
        with self.app.app_context():
            before = count_access_events(build_global_access_records())["total"]
            admin_user = self.db.session.execute(
                self.db.select(User).where(User.username == "Admin")
            ).scalar_one()
            now = campus_now()
            permit = issue_visitor_pass(
                admin_user, name, "Regression test",
                (now - timedelta(minutes=1)).isoformat(timespec="seconds"),
                (now + timedelta(hours=24)).isoformat(timespec="seconds"),
                email="visitor-history@example.test",
            )
            qr = visitor_token(permit)
            pass_id = permit.id

        client = self._signed_in_client("Admin")
        page = client.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        form = {"csrf_token": csrf.group(1).decode(), "qr_text": qr}

        entry_response = client.post("/admin/access-control", data=form)
        self.assertEqual(entry_response.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), entry_response.data)
        member_history = entry_response.data.split(b'<div class="history-card">', 1)[1]
        self.assertEqual(member_history.count(name.encode()), 1)
        self.assertIn("Pase de visitante".encode("utf-8"), member_history)

        with self.app.app_context():
            self.assertEqual(count_access_events(build_global_access_records())["total"], before + 1)
            visit = self.db.session.execute(
                self.db.select(VisitorAccessLog).where(VisitorAccessLog.pass_id == pass_id)
            ).scalar_one()
            # Real scans require a short delay. Adjust test fixture instead of sleeping.
            visit.checked_in_at = campus_now() - timedelta(seconds=10)
            self.db.session.commit()

        exit_response = client.post("/admin/access-control", data=form)
        self.assertEqual(exit_response.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), exit_response.data)
        updated_table = exit_response.data.split(b'<div class="history-card">', 1)[1]
        self.assertEqual(updated_table.count(name.encode()), 2)

        with self.app.app_context():
            combined = build_global_access_records()
            self.assertEqual(count_access_events(combined)["total"], before + 2)
            guest_events = [event for event in combined if event["name"] == name]
            self.assertEqual({event["action"] for event in guest_events}, {"check_in", "check_out"})
            self.assertTrue(all(event["role"] == "visitante" for event in guest_events))
            self.assertTrue(all(event["access_method"] == "visitor" for event in guest_events))
            self.assertTrue(all(event["user_check_ins"] == 1 and event["user_check_outs"] == 1
                                for event in guest_events))
            self.assertEqual(len([event for event in build_global_access_records(
                selected_role="visitante", search_text=name) if event["name"] == name]), 2)
            self.assertEqual(len([event for event in build_global_access_records(
                selected_role="estudiante") if event["name"] == name]), 0)
            day = campus_now().date().isoformat()
            filtered = build_global_access_records(
                selected_role="visitante", search_text=name,
                selected_date=day, date_format="%Y-%m-%d",
            )
            self.assertEqual(len(filtered), 2)

        history_page = client.get("/admin/attendance-history", query_string={
            "role": "visitante", "search": name
        })
        self.assertEqual(history_page.status_code, 200)
        self.assertEqual(history_page.data.count(name.encode()), 2)
        self.assertIn(b"Pase #", history_page.data)

    def test_admin_guest_pass_expiry_and_visitor_history(self):
        """Admin can create a non-account visitor pass; expired QR blocks reentry."""
        from app.models.user_model import User
        from app.models.visitor_access_model import VisitorPass, VisitorAccessLog
        from app.services.visitor_access_service import (
            issue_visitor_pass, visitor_token, visitor_code
        )
        from app.utils.local_time import campus_now
        with self.app.app_context():
            admin = self.db.session.execute(self.db.select(User).where(
                User.username == "Admin"
            )).scalar_one()
            now = campus_now()
            item = issue_visitor_pass(admin, "Guest Unique", "Campus tour",
                now.isoformat(timespec="seconds"),
                (now + timedelta(hours=24)).isoformat(timespec="seconds"))
            token, manual, pid = visitor_token(item), visitor_code(item), item.id
        admin_client = self._signed_in_client("Admin")
        self.assertEqual(admin_client.get(f"/credentials/visitor-pass/{pid}").status_code, 200)
        self.assertEqual(admin_client.get("/credentials/manage").status_code, 200)
        outsider = self._signed_in_client("StudentA")
        self.assertEqual(outsider.get(f"/credentials/visitor-pass/{pid}").status_code, 403)
        page = admin_client.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        first = admin_client.post("/admin/access-control", data={
            "csrf_token": csrf, "qr_text": token
        })
        self.assertIn("Escaneo correcto".encode("utf-8"), first.data)
        with self.app.app_context():
            log = self.db.session.execute(self.db.select(VisitorAccessLog).where(
                VisitorAccessLog.pass_id == pid
            )).scalar_one()
            log.checked_in_at = campus_now() - timedelta(seconds=10)
            saved_pass = self.db.session.get(VisitorPass, pid)
            saved_pass.expires_at = campus_now() - timedelta(seconds=1)
            self.db.session.commit()
        exit_resp = admin_client.post("/admin/access-control", data={
            "csrf_token": csrf, "pass_code": manual
        })
        self.assertIn("Escaneo correcto".encode("utf-8"), exit_resp.data)
        new_entry = admin_client.post("/admin/access-control", data={
            "csrf_token": csrf, "qr_text": token
        })
        self.assertIn("Escaneo rechazado".encode("utf-8"), new_entry.data)
        with self.app.app_context():
            logs = self.db.session.execute(self.db.select(VisitorAccessLog).where(
                VisitorAccessLog.pass_id == pid
            )).scalars().all()
            self.assertEqual(len(logs), 1)
            self.assertIsNotNone(logs[0].checked_out_at)

    def test_registered_visitor_account_requires_admin_permission(self):
        from werkzeug.security import generate_password_hash
        from app.models.user_model import User
        from app.models.visitor_access_model import VisitorRequest, VisitorPass
        from app.services.visitor_access_service import review_visitor_request
        from app.utils.local_time import campus_now
        with self.app.app_context():
            person = User(username="RecurringVisitor", email="recurring-visitor@example.test",
                first_name="Recurring", last_name="Visitor", phone="0000000000",
                role="visitante", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"))
            self.db.session.add(person)
            self.db.session.commit()
            uid = person.id
        visitor = self._signed_in_client("RecurringVisitor")
        page = visitor.get("/credentials/visitor")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(visitor.get("/credentials/manage").status_code, 403)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        now = campus_now()
        answer = visitor.post("/credentials/visitor/request", data={
            "csrf_token": csrf, "purpose": "Reunión de coordinación",
            "starts_at": now.isoformat(timespec="minutes"),
            "expires_at": (now + timedelta(hours=48)).isoformat(timespec="minutes"),
        })
        self.assertEqual(answer.status_code, 302)
        with self.app.app_context():
            request_row = self.db.session.execute(self.db.select(VisitorRequest).where(
                VisitorRequest.user_id == uid
            )).scalar_one()
            administrator = self.db.session.execute(self.db.select(User).where(
                User.username == "Admin"
            )).scalar_one()
            review_visitor_request(request_row.id, administrator, True)
            issued = self.db.session.execute(self.db.select(VisitorPass).where(
                VisitorPass.linked_user_id == uid
            )).scalar_one()
            pid = issued.id
        self.assertEqual(visitor.get(f"/credentials/visitor-pass/{pid}").status_code, 200)
        self.assertIn(b"QR", visitor.get("/credentials/visitor").data)

    def test_admin_dashboard_shows_population_presence_and_notices(self):
        client = self._signed_in_client()
        result = client.get("/admin/dashboard")
        self.assertEqual(result.status_code, 200)
        self.assertIn("Personas registradas por tipo".encode("utf-8"), result.data)
        self.assertIn("Monitor de usuarios".encode("utf-8"), result.data)
        self.assertIn("Dentro del campus".encode("utf-8"), result.data)
        self.assertNotIn("Avisos para la comunidad".encode("utf-8"), result.data)
        self.assertIn(b'href="/avisos"', result.data)
        self.assertIn("Avisos para la comunidad".encode("utf-8"), client.get("/admin/send-notices").data)
        self.assertIn(b"StudentA", result.data)
        self.assertIn(b"TeacherA", result.data)
        self.assertIn(b"StaffA", result.data)
        self.assertNotIn("Clases y asistencia".encode("utf-8"), result.data)
        filtered = client.get("/admin/dashboard?monitor_role=estudiante")
        self.assertEqual(filtered.status_code, 200)
        self.assertIn(b"StudentA", filtered.data)

    def test_role_targeted_notices_and_admin_only_publishing(self):
        from app.models.university_notice_model import UniversityNotice
        admin = self._signed_in_client()
        page = admin.get("/admin/dashboard")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(match)
        token = match.group(1).decode("utf-8")
        form = {"title": "Solo alumnos", "body": "Por favor consulten su horario actualizado.",
                "audience": "estudiante", "csrf_token": token}
        posted = admin.post("/admin/notices/create", data=form)
        self.assertEqual(posted.status_code, 302)
        with self.app.app_context():
            notice = self.db.session.execute(
                self.db.select(UniversityNotice).where(UniversityNotice.title == "Solo alumnos")
            ).scalar_one()
            notice_id = notice.id
            self.assertTrue(notice.is_active)
            self.assertEqual(notice.audience, "estudiante")

        student = self._signed_in_client("StudentA")
        teacher = self._signed_in_client("TeacherA")
        worker = self._signed_in_client("StaffA")
        self.assertNotIn("Solo alumnos".encode("utf-8"), student.get("/student/dashboard").data)
        self.assertIn("Solo alumnos".encode("utf-8"), student.get("/avisos").data)
        self.assertNotIn("Solo alumnos".encode("utf-8"), teacher.get("/professor/dashboard").data)
        self.assertNotIn("Solo alumnos".encode("utf-8"), worker.get("/personal/dashboard").data)

        student_page = student.get("/student/dashboard")
        student_token = re.search(rb'name="csrf_token" value="([^"]+)"', student_page.data)
        self.assertIsNotNone(student_token)
        unauthorized = student.post("/admin/notices/create", data={
            "title": "Fake notice", "body": "This user should not be able to post this",
            "audience": "all", "csrf_token": student_token.group(1).decode("utf-8"),
        })
        self.assertIn(unauthorized.status_code, (302, 403))
        with self.app.app_context():
            fake = self.db.session.execute(
                self.db.select(UniversityNotice).where(UniversityNotice.title == "Fake notice")
            ).scalar_one_or_none()
            self.assertIsNone(fake)

        archived = admin.post(f"/admin/notices/{notice_id}/archive",
                              data={"csrf_token": token})
        self.assertEqual(archived.status_code, 302)
        with self.app.app_context():
            self.assertFalse(self.db.session.get(UniversityNotice, notice_id).is_active)
        self.assertNotIn("Solo alumnos".encode("utf-8"), student.get("/student/dashboard").data)

        teacher_notice = admin.post("/admin/notices/create", data={
            "title": "Solo docentes",
            "body": "Revisar el calendario de clases.",
            "audience": "docente",
            "csrf_token": token,
        })
        self.assertEqual(teacher_notice.status_code, 302)
        self.assertNotIn("Solo docentes".encode("utf-8"), teacher.get("/professor/dashboard").data)
        self.assertIn("Solo docentes".encode("utf-8"), teacher.get("/avisos").data)
        self.assertNotIn("Solo docentes".encode("utf-8"), student.get("/student/dashboard").data)
        self.assertNotIn("Solo docentes".encode("utf-8"), worker.get("/personal/dashboard").data)
        with self.app.app_context():
            teacher_record = self.db.session.execute(
                self.db.select(UniversityNotice).where(UniversityNotice.title == "Solo docentes")
            ).scalar_one()
            teacher_record.is_active = False
            self.db.session.commit()


    def test_inbox_notifications_for_student_teacher_staff(self):
        """Recipient-only announcements, persistent read badges, and archived visibility."""
        from app.models.university_notice_model import UniversityNotice
        from app.models.university_notice_read_model import UniversityNoticeRead
        from app.models.user_model import User
        with self.app.app_context():
            admin_id = self.db.session.execute(
                self.db.select(User.id).where(User.username == "Admin")
            ).scalar_one()
            for suffix, audience in (
                ("All", "all"), ("Students", "estudiante"),
                ("Teachers", "docente"), ("Staff", "personal")
            ):
                self.db.session.add(UniversityNotice(
                    title="Inbox Scope " + suffix,
                    body="This role-targeted announcement is saved in the inbox.",
                    audience=audience, author_id=admin_id,
                    author_name="Admin", is_active=True,
                ))
            self.db.session.commit()
            notices = {
                item.title: item.id for item in self.db.session.execute(
                    self.db.select(UniversityNotice).where(
                        UniversityNotice.title.like("Inbox Scope %")
                    )
                ).scalars().all()
            }

        for username, route, own, hidden in (
            ("StudentA", "/student/dashboard", "Students", ("Teachers", "Staff")),
            ("TeacherA", "/professor/dashboard", "Teachers", ("Students", "Staff")),
            ("StaffA", "/personal/dashboard", "Staff", ("Students", "Teachers")),
        ):
            with self.subTest(role=username):
                client = self._signed_in_client(username)
                dashboard = client.get(route)
                self.assertIn(b'href="/avisos"', dashboard.data)
                self.assertIn(b'data-notice-sidebar-count', dashboard.data)
                self.assertNotIn(("Inbox Scope " + own).encode(), dashboard.data)
                inbox = client.get("/avisos")
                self.assertEqual(inbox.status_code, 200)
                self.assertIn(("Inbox Scope " + own).encode(), inbox.data)
                self.assertIn(b"Inbox Scope All", inbox.data)
                for excluded in hidden:
                    self.assertNotIn(("Inbox Scope " + excluded).encode(), inbox.data)

        student = self._signed_in_client("StudentA")
        inbox = student.get("/avisos")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', inbox.data)
        self.assertIsNotNone(csrf)
        token = csrf.group(1).decode()
        self.assertEqual(student.post(
            "/avisos/" + str(notices["Inbox Scope Teachers"]) + "/leer",
            data={"csrf_token": token}
        ).status_code, 404)
        self.assertEqual(student.post(
            "/avisos/" + str(notices["Inbox Scope Students"]) + "/leer"
        ).status_code, 400)
        self.assertEqual(student.post(
            "/avisos/" + str(notices["Inbox Scope Students"]) + "/leer",
            data={"csrf_token": token}
        ).status_code, 302)
        with self.app.app_context():
            student_id = self.db.session.execute(
                self.db.select(User.id).where(User.username == "StudentA")
            ).scalar_one()
            self.assertIsNotNone(self.db.session.get(
                UniversityNoticeRead, (student_id, notices["Inbox Scope Students"])
            ))
        self.assertEqual(student.post(
            "/avisos/leer-todos", data={"csrf_token": token}
        ).status_code, 302)
        self.assertIn(b'data-notice-unread-total>0 sin leer', student.get("/avisos").data)
        self.assertIn(b"Inbox Scope Students", student.get("/avisos").data)
        # Admin can archive a published notice; it stops appearing for recipients.
        admin = self._signed_in_client("Admin")
        admin_page = admin.get("/admin/dashboard")
        admin_token = re.search(rb'name="csrf_token" value="([^"]+)"', admin_page.data)
        self.assertIsNotNone(admin_token)
        archived = admin.post(
            "/admin/notices/" + str(notices["Inbox Scope Students"]) + "/archive",
            data={"csrf_token": admin_token.group(1).decode()}
        )
        self.assertEqual(archived.status_code, 302)
        self.assertNotIn(b"Inbox Scope Students", student.get("/avisos").data)
        self.assertEqual(admin.get("/avisos").status_code, 200)
        self.assertIn(b"Inbox Scope All", admin.get("/avisos").data)
        self.assertNotIn(b"Inbox Scope Students", admin.get("/avisos").data)
        self.assertNotEqual(self.app.test_client().get("/avisos").status_code, 200)

    def test_notifications_only_in_inbox_not_every_admin_page(self):
        """A published announcement must not appear in shared page layouts."""
        from app.models.university_notice_model import UniversityNotice
        from app.models.user_model import User
        with self.app.app_context():
            admin = self.db.session.execute(
                self.db.select(User).where(User.username == "Admin")
            ).scalar_one()
            notice = UniversityNotice(
                title="No Repeated Banner 2026", body="Welcome to the campus",
                audience="all", author_id=admin.id, author_name="Admin",
                is_active=True,
            )
            self.db.session.add(notice)
            self.db.session.commit()
            notice_id = notice.id
        try:
            for username, paths in (
                ("Admin", ("/admin/dashboard", "/admin/users",
                           "/admin/validation-codes", "/admin/access-control")),
                ("StudentA", ("/student/dashboard", "/student/access-control")),
                ("TeacherA", ("/professor/dashboard", "/professor/access-control")),
                ("StaffA", ("/personal/dashboard", "/personal/access-control")),
            ):
                client = self._signed_in_client(username)
                inbox = client.get("/avisos")
                self.assertEqual(inbox.status_code, 200)
                self.assertIn(b"No Repeated Banner 2026", inbox.data)
                for path in paths:
                    with self.subTest(username=username, path=path):
                        page = client.get(path)
                        self.assertEqual(page.status_code, 200)
                        self.assertNotIn(b"No Repeated Banner 2026", page.data)
            admin = self._signed_in_client("Admin")
            self.assertIn(b"No Repeated Banner 2026", admin.get("/admin/send-notices").data)
        finally:
            with self.app.app_context():
                notice = self.db.session.get(UniversityNotice, notice_id)
                if notice:
                    notice.is_active = False
                    self.db.session.commit()

    def test_unread_notification_redirects_once_then_dashboard_after_read(self):
        """Sign-in sends users to unread messages; read receipts survive new sessions."""
        from app.models.university_notice_model import UniversityNotice
        from app.models.user_model import User
        from werkzeug.security import generate_password_hash
        from app.services.university_notice_service import unread_notice_count
        with self.app.app_context():
            person = User(
                username="NoticeFirstMember", email="notice-first@example.test",
                first_name="Notice", last_name="First", phone="0000000000",
                role="estudiante", language="es", is_active_user=True,
                password_hash=generate_password_hash("TestingPassword123!"),
            )
            self.db.session.add(person)
            self.db.session.flush()
            self.db.session.add(UniversityNotice(
                title="Important First Login Notice",
                body="Please read this message before opening the dashboard.",
                audience="estudiante", author_id=person.id,
                author_name="Admin", is_active=True,
            ))
            self.db.session.commit()
            uid = person.id
        def sign_in(ip):
            client = self.app.test_client()
            client.environ_base["REMOTE_ADDR"] = ip
            login_page = client.get("/auth/login-page")
            csrf = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data).group(1).decode()
            response = client.post("/auth/login-page", data={
                "login": "NoticeFirstMember", "password": "TestingPassword123!",
                "csrf_token": csrf, "language": "es",
            })
            self.assertEqual(response.status_code, 302)
            return client, response.headers["Location"]

        first, destination = sign_in("203.0.113.51")
        self.assertTrue(destination.endswith("/avisos"), destination)
        inbox = first.get("/avisos")
        self.assertIn(b"Important First Login Notice", inbox.data)
        self.assertIn(b"data-notice-unread-total", inbox.data)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', inbox.data).group(1).decode()
        self.assertEqual(first.post("/avisos/leer-todos", data={
            "csrf_token": csrf
        }).status_code, 302)
        with self.app.app_context():
            person = self.db.session.get(User, uid)
            self.assertEqual(unread_notice_count(person), 0)
        second, destination = sign_in("203.0.113.52")
        self.assertTrue(destination.endswith("/student/dashboard"), destination)
        self.assertIn(b"Important First Login Notice", second.get("/avisos").data)
        self.assertNotIn(b"Important First Login Notice", second.get("/student/dashboard").data)

    def test_notice_form_protected_by_csrf(self):
        client = self._signed_in_client()
        response = client.post("/admin/notices/create", data={
            "title": "Missing CSRF", "body": "Should never be published", "audience": "all"
        })
        self.assertEqual(response.status_code, 400)

    def test_admin_history_shows_other_user_checkin_and_checkout(self):
        """A scan of someone else's QR must appear in the admin history."""
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.models.access_scan_pair_model import AccessScanPair
        from app.services.scan_token_service import issue_access_credential
        from werkzeug.security import generate_password_hash

        with self.app.app_context():
            person = User(
                username="QRHistoryTarget", email="qr-history-target@example.test",
                first_name="QRHistory", last_name="Target",
                role="estudiante", phone="0000000000", language="es",
                password_hash=generate_password_hash("TestingPassword123!"),
                is_active_user=True,
            )
            self.db.session.add(person)
            self.db.session.commit()
            person_id = person.id
            qr_text, _ = issue_access_credential(person)

        admin = self._signed_in_client("Admin")
        page = admin.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        payload = {"csrf_token": csrf.group(1).decode(), "qr_text": qr_text}

        first = admin.post("/admin/access-control", data=payload)
        self.assertEqual(first.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), first.data)
        history = first.data.split(b'<div class="history-card">', 1)[1]
        self.assertIn(b"QRHistory Target</td>", history)
        first_row = history.split(b"QRHistory Target</td>", 1)[1].split(b"</tr>", 1)[0]
        self.assertIn("Dentro del campus".encode("utf-8"), first_row)
        self.assertEqual(history.count(b"QRHistory Target</td>"), 1)
        self.assertIn("Entradas registradas".encode("utf-8"), history)
        self.assertIn("Salidas registradas".encode("utf-8"), history)

        with self.app.app_context():
            log = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == person_id
            )).scalar_one()
            pair = self.db.session.execute(self.db.select(AccessScanPair).where(
                AccessScanPair.access_log_id == log.id
            )).scalar_one()
            pair.checked_in_at -= timedelta(seconds=5)
            self.db.session.commit()

        second = admin.post("/admin/access-control", data=payload)
        self.assertEqual(second.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), second.data)
        history = second.data.split(b'<div class="history-card">', 1)[1]
        row = history.split(b"QRHistory Target</td>", 1)[1].split(b"</tr>", 1)[0]
        self.assertIn("Fuera del campus".encode("utf-8"), row)
        self.assertEqual(history.count(b"QRHistory Target</td>"), 2)
        self.assertIn(b">1 / 1</td>", row)
        with self.app.app_context():
            log = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == person_id
            )).scalar_one()
            self.assertIsNotNone(log.check_out_time)
            check_out_text = log.check_out_time.strftime("%I:%M %p").encode()
            date_text = log.access_date.strftime("%m/%d/%Y")

        self.assertIn(check_out_text, row)
        filtered = admin.get("/admin/access-control", query_string={"date": date_text})
        self.assertIn(b"QRHistory Target</td>", filtered.data)
        self.assertIn(check_out_text, filtered.data)

        # The second visit is a new entry and exit, each with its own row.
        with self.app.app_context():
            person = self.db.session.get(User, person_id)
            second_qr, _ = issue_access_credential(person)
        new_payload = {"csrf_token": payload["csrf_token"], "qr_text": second_qr}
        third = admin.post("/admin/access-control", data=new_payload)
        self.assertIn("Escaneo correcto".encode("utf-8"), third.data)
        events = third.data.split(b'<div class="history-card">', 1)[1]
        self.assertEqual(events.count(b"QRHistory Target</td>"), 3)

        with self.app.app_context():
            newest = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == person_id,
                AccessLog.check_out_time.is_(None),
            )).scalar_one()
            pair = self.db.session.execute(self.db.select(AccessScanPair).where(
                AccessScanPair.access_log_id == newest.id
            )).scalar_one()
            pair.checked_in_at -= timedelta(seconds=5)
            self.db.session.commit()

        fourth = admin.post("/admin/access-control", data=new_payload)
        self.assertIn("Escaneo correcto".encode("utf-8"), fourth.data)
        events = fourth.data.split(b'<div class="history-card">', 1)[1]
        self.assertEqual(events.count(b"QRHistory Target</td>"), 4)
        self.assertEqual(events.count(b">2 / 2</td>"), 4)
        full_page = admin.get("/admin/attendance-history", query_string={"search": "QRHistoryTarget"})
        self.assertEqual(full_page.status_code, 200)
        self.assertEqual(full_page.data.count(b"QRHistory Target</td>"), 4)
        self.assertIn("Total de movimientos".encode("utf-8"), full_page.data)

    def test_admin_access_control_contains_camera_and_confirm_button(self):
        client = self._signed_in_client()
        page = client.get("/admin/access-control")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="adminAccessQrForm"', page.data)
        self.assertIn(b'data-qr-start', page.data)
        self.assertIn(b'data-qr-video', page.data)
        self.assertIn(b'data-qr-photo', page.data)
        self.assertEqual(page.data.count(b"js/qr-camera.js"), 1)
        self.assertEqual(page.data.count(b"js/vendor/jsQR.js"), 1)
        self.assertIn("Confirmar acceso".encode("utf-8"), page.data)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        rejected = client.post("/admin/access-control", data={
            "csrf_token": csrf.group(1).decode("utf-8"),
            "qr_text": "UT-UPBC-0001",
        })
        self.assertEqual(rejected.status_code, 200)
        self.assertIn("Escaneo rechazado".encode("utf-8"), rejected.data)

    def test_admin_access_control_scans_signed_qr_on_same_page(self):
        from werkzeug.security import generate_password_hash
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_scan_token
        with self.app.app_context():
            student = User(
                username="AccessPageUser",
                email="access-page-user@example.test",
                first_name="Access", last_name="Page",
                role="estudiante", phone="0000000000", language="es",
                password_hash=generate_password_hash("TestingPassword123!"),
                is_active_user=True,
            )
            self.db.session.add(student)
            self.db.session.commit()
            signed_qr = issue_scan_token(student)
            student_id = student.id

        client = self._signed_in_client()
        page = client.get("/admin/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        payload = {
            "csrf_token": csrf.group(1).decode("utf-8"),
            "qr_text": signed_qr,
        }
        processed = client.post("/admin/access-control", data=payload)
        self.assertEqual(processed.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), processed.data)
        self.assertIn(b"Access Page", processed.data)
        self.assertIn(b'id="adminAccessQrForm"', processed.data)
        with self.app.app_context():
            self.assertEqual(
                self.db.session.execute(
                    self.db.select(self.db.func.count(AccessLog.id)).where(
                        AccessLog.student_id == student_id
                    )
                ).scalar_one(), 1
            )

        repeated = client.post("/admin/access-control", data=payload)
        self.assertEqual(repeated.status_code, 200)
        self.assertIn("Escaneo rechazado".encode("utf-8"), repeated.data)
        with self.app.app_context():
            self.assertEqual(
                self.db.session.execute(
                    self.db.select(self.db.func.count(AccessLog.id)).where(
                        AccessLog.student_id == student_id
                    )
                ).scalar_one(), 1
            )

    def test_scanner_rejects_unsigned_identifier(self):
        client = self._signed_in_client()
        page = client.get("/admin/access-control/scanner")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(token)
        response = client.post("/admin/access-control/scanner", data={
            "qr_text": "UT-UPBC-0001",
            "csrf_token": token.group(1).decode("utf-8"),
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"QR", response.data)

    def test_login_page_and_csrf_work_together(self):
        client = self.app.test_client()
        response = client.get("/auth/login-page")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        response = client.post("/auth/login-page", data={
            "login": "aDmIn", "password": "TestingPassword123!",
            "csrf_token": match.group(1).decode("utf-8"), "language": "es"
        })
        self.assertIn(response.status_code, (302, 303))


    def test_get_logout_is_not_allowed(self):
        client = self._signed_in_client()
        self.assertEqual(client.get("/auth/logout").status_code, 405)
        dashboard = client.get("/admin/dashboard")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', dashboard.data)
        self.assertIsNotNone(token)
        response = client.post("/auth/logout", data={
            "csrf_token": token.group(1).decode("utf-8")
        })
        self.assertIn(response.status_code, (302, 303))

    def test_valid_signed_qr_operator_scan_creates_one_access_event(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_scan_token

        client = self._signed_in_client()
        with self.app.app_context():
            student = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            signed = issue_scan_token(student)
            student_id = student.id
        page = client.get("/admin/access-control/scanner")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        data = {"qr_text": signed, "csrf_token": csrf.group(1).decode("utf-8")}
        first = client.post("/admin/access-control/scanner", data=data)
        self.assertEqual(first.status_code, 200)
        with self.app.app_context():
            logs = self.db.session.execute(self.db.select(AccessLog).where(
                AccessLog.student_id == student_id
            )).scalars().all()
            self.assertEqual(len(logs), 1)
        second = client.post("/admin/access-control/scanner", data=data)
        self.assertEqual(second.status_code, 200)
        with self.app.app_context():
            count = self.db.session.execute(self.db.select(self.db.func.count(AccessLog.id)).where(
                AccessLog.student_id == student_id
            )).scalar_one()
            self.assertEqual(count, 1)

    def test_admin_and_teacher_camera_script_present(self):
        for username, path in (
            ("Admin", "/admin/access-control"),
            ("TeacherA", "/professor/access-control"),
            ("StaffA", "/personal/access-control")
        ):
            with self.subTest(username=username):
                client = self._signed_in_client(username)
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data.count(b"js/qr-camera.js"), 1)
                self.assertEqual(response.data.count(b"js/vendor/jsQR.js"), 1)
                self.assertIn(b"data-qr-start", response.data)
                self.assertIn(b"data-qr-video", response.data)
                self.assertIn(b"data-qr-stage", response.data)
                self.assertIn(b"data-qr-overlay", response.data)
                self.assertIn(b"data-qr-outline", response.data)
                self.assertIn(b"data-qr-detected-badge", response.data)

    def test_student_has_one_access_page_with_personal_qr_and_history(self):
        client = self._signed_in_client("StudentA")
        page = client.get("/student/access-control")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="studentPersonalAccess"', page.data)
        self.assertIn(b"data:image/png;base64,", page.data)
        self.assertIn(b"EST-", page.data)
        self.assertIn("Historial de Acceso".encode("utf-8"), page.data)
        self.assertNotIn(b'href="/student/access-control/scanner"', page.data)
        self.assertNotIn(b'url_for(\'student_views.access_control_check_in\')', page.data)
        self.assertIn(b'id="studentAccessCamera"', page.data)
        self.assertIn(b'data-qr-start', page.data)
        self.assertIn(b'data-qr-video', page.data)
        self.assertIn(b'data-qr-stage', page.data)
        self.assertIn(b'data-qr-overlay', page.data)
        self.assertIn(b'data-qr-outline', page.data)
        self.assertIn(b'data-qr-detected-badge', page.data)
        self.assertIn(b'name="pass_code"', page.data)
        self.assertIn(b'js/qr-camera.js', page.data)
        self.assertEqual(page.data.count(b"js/qr-camera.js"), 1)
        self.assertEqual(page.data.count(b"js/vendor/jsQR.js"), 1)
        old = client.get("/student/access-control/scanner")
        self.assertEqual(old.status_code, 302)
        self.assertTrue(old.headers["Location"].endswith("/student/access-control"))

    def test_student_local_scanner_records_own_entry_exit_and_global_history(self):
        """Local student scans are self-reported; official gate scanning stays operator-only."""
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.models.access_scan_pair_model import AccessScanPair
        from app.services.scan_token_service import issue_access_credential

        with self.app.app_context():
            student = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            other = self.db.session.execute(
                self.db.select(User).where(User.username == "TeacherA")
            ).scalar_one()
            signed_qr, temporary_code = issue_access_credential(student)
            other_qr, _ = issue_access_credential(other)
            student_id = student.id
            preexisting_log_ids = set(self.db.session.execute(
                self.db.select(AccessLog.id).where(AccessLog.student_id == student_id)
            ).scalars().all())

        client = self._signed_in_client("StudentA")
        self.app.config["ALLOW_LOCAL_SELF_ACCESS_SCANS"] = True
        try:
            page = client.get("/student/access-control")
            csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
            self.assertIsNotNone(csrf)
            token = csrf.group(1).decode("utf-8")

            rejected = client.post("/student/access-control", data={
                "qr_text": other_qr, "csrf_token": token,
            })
            self.assertIn("Escaneo rechazado".encode("utf-8"), rejected.data)

            entry = client.post("/student/access-control", data={
                "qr_text": signed_qr, "csrf_token": token,
            })
            self.assertEqual(entry.status_code, 200)
            self.assertIn("Entrada registrada".encode("utf-8"), entry.data)
            self.assertIn(b"data-access-count-in>1</strong>", entry.data)

            # Two camera submissions within two seconds must not fake a checkout.
            fast = client.post("/student/access-control", data={
                "pass_code": temporary_code, "csrf_token": token,
            })
            self.assertIn("Escaneo rechazado".encode("utf-8"), fast.data)
            with self.app.app_context():
                log = self.db.session.execute(self.db.select(AccessLog).where(
                    AccessLog.student_id == student_id,
                    AccessLog.check_out_time.is_(None),
                )).scalar_one()
                self.assertEqual(log.access_method, "self_service")
                pair = self.db.session.execute(self.db.select(AccessScanPair).where(
                    AccessScanPair.access_log_id == log.id,
                )).scalar_one()
                pair.checked_in_at -= timedelta(seconds=5)
                self.db.session.commit()

            exit_result = client.post("/student/access-control", data={
                "pass_code": temporary_code, "csrf_token": token,
            })
            self.assertIn("Salida registrada".encode("utf-8"), exit_result.data)
            self.assertIn(b"data-access-count-out>1</strong>", exit_result.data)
            admin = self._signed_in_client("Admin")
            history = admin.get("/admin/attendance-history", query_string={"search": "StudentA"})
            self.assertEqual(history.status_code, 200)
            self.assertIn("Autoregistro local".encode("utf-8"), history.data)

            with self.app.app_context():
                student = self.db.session.get(User, student_id)
                new_qr, _ = issue_access_credential(student)
            next_entry = client.post("/student/access-control", data={
                "qr_text": new_qr, "csrf_token": token,
            })
            self.assertIn("Entrada registrada".encode("utf-8"), next_entry.data)
            with self.app.app_context():
                logs = self.db.session.execute(self.db.select(AccessLog).where(
                    AccessLog.student_id == student_id
                )).scalars().all()
                self.assertEqual(len(logs), 2)
        finally:
            self.app.config["ALLOW_LOCAL_SELF_ACCESS_SCANS"] = False
            # Isolate this integration test: never leave new StudentA access
            # records behind for subsequent tests that use the same fixture.
            with self.app.app_context():
                created = [
                    row_id for row_id in self.db.session.execute(
                        self.db.select(AccessLog.id).where(
                            AccessLog.student_id == student_id
                        )
                    ).scalars().all() if row_id not in preexisting_log_ids
                ]
                if created:
                    self.db.session.execute(self.db.delete(AccessScanPair).where(
                        AccessScanPair.access_log_id.in_(created)
                    ))
                    self.db.session.execute(self.db.delete(AccessLog).where(
                        AccessLog.id.in_(created)
                    ))
                    self.db.session.commit()

    def test_hosted_mode_never_accepts_student_self_scans(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_access_credential
        client = self._signed_in_client("StudentA")
        with self.app.app_context():
            student = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            qr, _ = issue_access_credential(student)
            count_before = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
                .where(AccessLog.student_id == student.id)
            ).scalar_one()
        self.app.config["ALLOW_LOCAL_SELF_ACCESS_SCANS"] = False
        page = client.get("/student/access-control")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        response = client.post("/student/access-control", data={
            "qr_text": qr, "csrf_token": token,
        })
        self.assertIn("Código verificado".encode("utf-8"), response.data)
        with self.app.app_context():
            count_after = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
                .where(AccessLog.student_id == student.id)
            ).scalar_one()
            self.assertEqual(count_before, count_after)

    def test_student_cannot_self_check_in_or_out(self):
        from app.models.access_log_model import AccessLog
        client = self._signed_in_client("StudentA")
        page = client.get("/student/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        fields = {"csrf_token": csrf.group(1).decode("utf-8")}
        with self.app.app_context():
            initial = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
            ).scalar_one()
        for path in (
            "/student/access-control/check-in",
            "/student/access-control/check-out",
            "/student/access-control/scanner",
        ):
            response = client.post(path, data=fields)
            self.assertEqual(response.status_code, 403, path)
        with self.app.app_context():
            final = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
            ).scalar_one()
        self.assertEqual(initial, final)

    def test_operator_scanner_is_inside_control_de_acceso(self):
        for username, prefix in (("TeacherA", "/professor"), ("StaffA", "/personal")):
            with self.subTest(role=username):
                client = self._signed_in_client(username)
                page = client.get(prefix + "/access-control")
                self.assertEqual(page.status_code, 200)
                self.assertIn(b'id="operatorAccessScanner"', page.data)
                self.assertIn(b'name="pass_code"', page.data)
                self.assertIn(b'data-qr-start', page.data)
                self.assertEqual(page.data.count(b"js/qr-camera.js"), 1)
                self.assertNotIn((prefix + "/access-control/scanner").encode(), page.data)
                old = client.get(prefix + "/access-control/scanner")
                self.assertEqual(old.status_code, 302)
                self.assertEqual(old.headers["Location"].split("?")[0], prefix + "/access-control")

    def test_camera_decoding_fallback_is_self_hosted(self):
        client = self._signed_in_client()
        library = client.get("/static/js/vendor/jsQR.js")
        scanner = client.get("/static/js/qr-camera.js")
        self.assertEqual(library.status_code, 200)
        self.assertEqual(scanner.status_code, 200)
        self.assertIn(b"jsQR", library.data)
        self.assertIn(b"getUserMedia", scanner.data)
        self.assertIn(b"window.jsQR", scanner.data)
        self.assertNotIn(b"BarcodeDetector", scanner.data)
        # Authorized camera capture submits the CSRF-protected form once.
        self.assertIn(b"form.requestSubmit", scanner.data)
        self.assertIn(b"foundQr(result.data, true, result)", scanner.data)
        self.assertIn(b"loc.topLeftCorner", scanner.data)
        self.assertIn(b"loc.bottomRightCorner", scanner.data)
        self.assertIn(b'outline.setAttribute("points"', scanner.data)
        self.assertIn(b'overlay.setAttribute("viewBox"', scanner.data)
        self.assertIn(b'video.pause()', scanner.data)
        self.assertIn(b'}, 1000)', scanner.data)
        self.assertNotIn(b"form.submit()", scanner.data)

    def test_each_role_displays_own_secure_qr_and_temporary_code(self):
        """Four permanent roles display a stable per-person QR and manual code."""
        from app.services.permanent_credential_service import (
            resolve_permanent_credential, permanent_credential_for_user
        )
        from app.models.user_model import User
        paths = [
            ("Admin", "/admin/access-control", "ADM"),
            ("StudentA", "/student/access-control", "EST"),
            ("TeacherA", "/professor/access-control", "DOC"),
            ("StaffA", "/personal/access-control", "PER"),
        ]
        issued = set()
        for username, path, prefix in paths:
            with self.subTest(username=username):
                client = self._signed_in_client(username)
                first = client.get(path)
                second = client.get(path)
                self.assertEqual(first.status_code, 200)
                self.assertEqual(second.status_code, 200)
                self.assertIn(b"data:image/png;base64,", first.data)
                self.assertEqual(
                    re.search(rb'data:image/png;base64,[A-Za-z0-9+/=]+', first.data).group(0),
                    re.search(rb'data:image/png;base64,[A-Za-z0-9+/=]+', second.data).group(0)
                )
                with self.app.app_context():
                    person = self.db.session.execute(self.db.select(User).where(
                        User.username == username
                    )).scalar_one()
                    token, code = permanent_credential_for_user(person)
                    again, again_code = permanent_credential_for_user(person)
                    self.assertEqual((token, code), (again, again_code))
                    self.assertTrue(code.startswith(prefix + "-"))
                    self.assertNotIn(code, issued)
                    issued.add(code)
                    self.assertEqual(resolve_permanent_credential(token)[0].id, person.id)
                    self.assertEqual(resolve_permanent_credential(code)[0].id, person.id)
    def test_two_people_in_same_role_get_independent_codes(self):
        from app.models.user_model import User
        from app.services.scan_token_service import issue_access_credential, resolve_scan_token
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            existing = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            second = User(
                username="StudentBUniqueCode", email="student-b-unique@example.test",
                first_name="Second", last_name="Student", phone="0000000000",
                role="estudiante", language="es",
                password_hash=generate_password_hash("TestingPassword123!"),
                is_active_user=True
            )
            self.db.session.add(second)
            self.db.session.commit()
            qr1, code1 = issue_access_credential(existing)
            qr2, code2 = issue_access_credential(second)
            self.assertTrue(code1.startswith("EST-"))
            self.assertTrue(code2.startswith("EST-"))
            self.assertNotEqual(code1, code2)
            self.assertNotEqual(qr1, qr2)
            user1, _ = resolve_scan_token(code1)
            user2, _ = resolve_scan_token(code2)
            self.assertEqual(user1.id, existing.id)
            self.assertEqual(user2.id, second.id)


    def test_manual_access_code_registers_once_and_invalidates_matching_qr(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_access_credential, resolve_scan_token
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            person = User(
                username="PasscodeMember", email="passcode.member@example.test",
                first_name="Passcode", last_name="Member",
                phone="0000000000", role="estudiante", language="es",
                password_hash=generate_password_hash("TestingPassword123!"),
                is_active_user=True,
            )
            self.db.session.add(person)
            self.db.session.commit()
            signed_qr, manual_code = issue_access_credential(person)
            user_id = person.id
            self.assertTrue(manual_code.startswith("EST-"), manual_code)
            self.assertEqual(len(manual_code.split("-", 1)[1].replace("-", "")), 16)
            with self.assertRaises(ValueError):
                resolve_scan_token("DOC-" + manual_code.split("-", 1)[1])
            with self.assertRaises(ValueError):
                resolve_scan_token(manual_code.split("-", 1)[1])
            identified, _ = resolve_scan_token(manual_code.replace("-", "").lower())
            self.assertEqual(identified.id, user_id)

        admin = self._signed_in_client()
        access = admin.get("/admin/access-control")
        csrf_match = re.search(rb'name="csrf_token" value="([^"]+)"', access.data)
        self.assertIsNotNone(csrf_match)
        data = {"csrf_token": csrf_match.group(1).decode("utf-8"), "pass_code": manual_code}
        first = admin.post("/admin/access-control", data=data)
        self.assertEqual(first.status_code, 200)
        self.assertIn("Escaneo correcto".encode("utf-8"), first.data)
        with self.app.app_context():
            self.assertEqual(self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id)).where(
                    AccessLog.student_id == user_id
                )
            ).scalar_one(), 1)

        repeated = admin.post("/admin/access-control", data=data)
        self.assertEqual(repeated.status_code, 200)
        self.assertIn("Escaneo rechazado".encode("utf-8"), repeated.data)
        by_qr = admin.post("/admin/access-control", data={
            "csrf_token": data["csrf_token"], "qr_text": signed_qr
        })
        self.assertEqual(by_qr.status_code, 200)
        self.assertIn("Escaneo rechazado".encode("utf-8"), by_qr.data)
        with self.app.app_context():
            self.assertEqual(self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id)).where(
                    AccessLog.student_id == user_id
                )
            ).scalar_one(), 1)

    def test_admin_can_deactivate_and_reactivate_without_deleting_user(self):
        from app.models.user_model import User
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            user = User(
                username="SuspendTest", email="suspend@example.test",
                first_name="Suspend", last_name="Test",
                phone="0000000000", role="estudiante", language="es",
                password_hash=generate_password_hash("TestingPassword123!"),
                is_active_user=True
            )
            self.db.session.add(user)
            self.db.session.commit()
            user_id = user.id

        client = self._signed_in_client()
        page = client.get(f"/admin/users/{user_id}/edit")
        self.assertEqual(page.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(match)
        token = match.group(1).decode("utf-8")
        response = client.post(f"/admin/users/{user_id}/toggle-active",
                               data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertFalse(self.db.session.get(User, user_id).is_active_user)
        response = client.post(f"/admin/users/{user_id}/toggle-active",
                               data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertTrue(self.db.session.get(User, user_id).is_active_user)

    def test_account_security_records_are_cleaned_on_allowed_user_deletion(self):
        """The new security rows must not prevent authorized account deletion."""
        from app.models.user_model import User
        from app.models.password_history_model import PasswordHistory
        from app.models.login_security_model import LoginSecurityState
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            user = User(
                username="DeleteSecurityTest", email="deletesecurity@example.test",
                first_name="Delete", last_name="Security",
                phone="0000000000", role="estudiante", language="es",
                password_hash=generate_password_hash("TestingPassword123!"),
                is_active_user=True,
            )
            self.db.session.add(user)
            self.db.session.flush()
            user_id = user.id
            self.db.session.add(PasswordHistory(
                user_id=user_id, password_hash=generate_password_hash("History phrase 2026!")
            ))
            self.db.session.add(LoginSecurityState(user_id=user_id, failed_attempts=2))
            self.db.session.commit()
        admin = self._signed_in_client("Admin")
        page = admin.get(f"/admin/users/{user_id}/delete")
        self.assertEqual(page.status_code, 200)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        response = admin.post(f"/admin/users/{user_id}/delete", data={
            "csrf_token": csrf, "confirmation_text": "DELETE"
        })
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertIsNone(self.db.session.get(User, user_id))
            self.assertIsNone(self.db.session.get(LoginSecurityState, user_id))
            self.assertEqual(self.db.session.execute(
                self.db.select(self.db.func.count(PasswordHistory.id)).where(
                    PasswordHistory.user_id == user_id
                )
            ).scalar_one(), 0)

    def test_attendance_history_blocks_permanent_user_deletion(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.routes.admin_views import can_delete_user
        from app.utils.local_time import campus_now
        from werkzeug.security import generate_password_hash
        with self.app.app_context():
            user = User(
                username="HistoryTest", email="history@example.test",
                first_name="History", last_name="Test",
                phone="0000000000", role="estudiante", language="es",
                password_hash=generate_password_hash("TestingPassword123!"),
                is_active_user=True
            )
            self.db.session.add(user)
            self.db.session.flush()
            now = campus_now()
            self.db.session.add(AccessLog(
                student_id=user.id, access_date=now.date(),
                check_in_time=now, access_status="checked_in", access_method="qr"
            ))
            self.db.session.commit()
            admin = self.db.session.execute(
                self.db.select(User).where(User.username == "Admin")
            ).scalar_one()
            allowed, reason = can_delete_user(user, admin)
            self.assertFalse(allowed)
            self.assertIn("history", reason.lower())


    def test_registration_consumes_validation_code_once(self):
        from app.models.user_model import User
        from app.services.validation_code_service import create_validation_code
        with self.app.app_context():
            admin = self.db.session.execute(
                self.db.select(User).where(User.username == "Admin")
            ).scalar_one()
            code = create_validation_code(admin.id, "estudiante", expires_in_hours=2).code

        client = self.app.test_client()
        payload = {
            "first_name": "Atomic", "last_name": "Register",
            "username": "AtomicTestUser", "email": "atomic@example.test",
            "phone": "6861234567", "password": "TestingPassword123!",
            "role": "estudiante", "validation_code": code,
        }
        first = client.post("/auth/register", json=payload)
        self.assertEqual(first.status_code, 201, first.get_json())
        second_payload = dict(payload, username="AtomicSecondUser",
                              email="atomic2@example.test")
        second = client.post("/auth/register", json=second_payload)
        self.assertEqual(second.status_code, 403)
        with self.app.app_context():
            first_user = self.db.session.execute(
                self.db.select(User).where(User.username == "AtomicTestUser")
            ).scalar_one_or_none()
            second_user = self.db.session.execute(
                self.db.select(User).where(User.username == "AtomicSecondUser")
            ).scalar_one_or_none()
            self.assertIsNotNone(first_user)
            self.assertIsNone(second_user)


    def test_private_response_security_headers(self):
        response = self.app.test_client().get("/auth/login-page")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))

    def test_production_rejects_weak_session_secret(self):
        from app import create_app
        previous_env = os.environ.get("UNITRACK_ENV")
        previous_secret = os.environ.get("SECRET_KEY")
        try:
            os.environ["UNITRACK_ENV"] = "production"
            os.environ["SECRET_KEY"] = "weak"
            with self.assertRaises(RuntimeError):
                create_app()
        finally:
            if previous_env is None:
                os.environ.pop("UNITRACK_ENV", None)
            else:
                os.environ["UNITRACK_ENV"] = previous_env
            if previous_secret is None:
                os.environ.pop("SECRET_KEY", None)
            else:
                os.environ["SECRET_KEY"] = previous_secret


if __name__ == "__main__":
    unittest.main()
