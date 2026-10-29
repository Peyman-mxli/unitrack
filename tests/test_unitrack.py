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
                                   ("TeacherA", "docente")]:
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

    def test_login_username_case_insensitive(self):
        from app.services.user_service import get_user_by_username
        with self.app.app_context():
            for typed in ("Admin", "admin", "ADMIN", "aDmIn"):
                self.assertEqual(get_user_by_username(typed).username, "Admin")

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

    def test_academic_absence_requires_finalization(self):
        from app.models.user_model import User
        from app.models.academic_models import UniversityClass, ClassEnrollment, ClassMeeting
        from app.services.attendance_service import get_student_attendance_summary
        with self.app.app_context():
            student = self.db.session.execute(self.db.select(User).where(User.username == "StudentA")).scalar_one()
            teacher = self.db.session.execute(self.db.select(User).where(User.username == "TeacherA")).scalar_one()
            course = UniversityClass(code="TEST101", title="Test Course", professor_id=teacher.id)
            self.db.session.add(course)
            self.db.session.flush()
            self.db.session.add(ClassEnrollment(class_id=course.id, student_id=student.id,
                                                 enrolled_at=datetime.utcnow()-timedelta(days=4)))
            meeting = ClassMeeting(class_id=course.id, starts_at=datetime.utcnow()-timedelta(days=2),
                                   ends_at=datetime.utcnow()-timedelta(days=2)+timedelta(hours=1))
            self.db.session.add(meeting)
            self.db.session.commit()
            before = get_student_attendance_summary(student.id, selected_class_name=course.code)
            self.assertEqual(before["absent_count"], 0)
            meeting.finalized_at = datetime.utcnow()
            self.db.session.commit()
            after = get_student_attendance_summary(student.id, selected_class_name=course.code)
            self.assertEqual(after["absent_count"], 1)

    def test_csrf_rejects_unprotected_form(self):
        response = self.app.test_client().post("/auth/login-page", data={
            "login": "Admin", "password": "TestingPassword123!"
        })
        self.assertEqual(response.status_code, 400)

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


if __name__ == "__main__":
    unittest.main()
