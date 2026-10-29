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

    def test_administrator_pages_render(self):
        client = self._signed_in_client()
        for url in (
            "/admin/dashboard", "/admin/users", "/admin/validation-codes",
            "/admin/configuration", "/admin/attendance-history",
            "/attendance/classes", "/admin/access-control/scanner",
        ):
            with self.subTest(url=url):
                response = client.get(url)
                self.assertEqual(response.status_code, 200, url)
                self.assertIn(b"UniTrack", response.data)

    def test_teacher_class_management_page(self):
        client = self._signed_in_client("TeacherA")
        response = client.get("/attendance/classes")
        self.assertEqual(response.status_code, 200)

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
            ("Admin", "/admin/access-control/scanner"),
            ("TeacherA", "/professor/access-control/scanner"),
            ("StaffA", "/personal/access-control/scanner")
        ):
            with self.subTest(username=username):
                client = self._signed_in_client(username)
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data.count(b"js/qr-camera.js"), 1)
                self.assertEqual(response.data.count(b"js/vendor/jsQR.js"), 1)
                self.assertIn(b"data-qr-start", response.data)
                self.assertIn(b"data-qr-video", response.data)

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
        # QR capture never silently submits an access event.
        self.assertNotIn(b"form.requestSubmit()", scanner.data)
        self.assertNotIn(b"form.submit()", scanner.data)

    def test_student_cannot_manage_academic_classes(self):
        client = self._signed_in_client("StudentA")
        self.assertEqual(client.get("/attendance/classes").status_code, 403)


    def test_teacher_class_workflow_and_student_report(self):
        from app.models.academic_models import UniversityClass, ClassMeeting, ClassEnrollment
        from app.models.user_model import User
        from app.services.attendance_service import get_student_attendance_summary
        from app.utils.local_time import campus_now
        client = self._signed_in_client("TeacherA")
        page = client.get("/attendance/classes")
        csrf_match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf_match)
        csrf = csrf_match.group(1).decode("utf-8")
        create = client.post("/attendance/classes/create", data={
            "code": "ENDTOEND101", "title": "Integration Test Class",
            "csrf_token": csrf,
        })
        self.assertEqual(create.status_code, 302)
        with self.app.app_context():
            course = self.db.session.execute(
                self.db.select(UniversityClass).where(UniversityClass.code == "ENDTOEND101")
            ).scalar_one()
            course_id = course.id

        enroll = client.post(f"/attendance/classes/{course_id}/enroll", data={
            "student_identifier": "StudentA", "csrf_token": csrf,
        })
        self.assertEqual(enroll.status_code, 302)
        now = campus_now()
        # Simulate a meeting after the student's existing enrollment.
        with self.app.app_context():
            student = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            membership = self.db.session.execute(self.db.select(ClassEnrollment).where(
                ClassEnrollment.class_id == course_id,
                ClassEnrollment.student_id == student.id
            )).scalar_one()
            membership.enrolled_at = now - timedelta(days=3)
            self.db.session.commit()
            student_id = student.id

        start = now - timedelta(days=1)
        end = start + timedelta(hours=1)
        schedule = client.post(f"/attendance/classes/{course_id}/meeting", data={
            "starts_at": start.strftime("%Y-%m-%dT%H:%M"),
            "ends_at": end.strftime("%Y-%m-%dT%H:%M"),
            "csrf_token": csrf
        })
        self.assertEqual(schedule.status_code, 302)
        with self.app.app_context():
            meeting = self.db.session.execute(
                self.db.select(ClassMeeting).where(ClassMeeting.class_id == course_id)
            ).scalar_one()
            meeting_id = meeting.id
        mark = client.post(f"/attendance/meetings/{meeting_id}/mark", data={
            "student_id": student_id, "status": "Present", "csrf_token": csrf
        })
        self.assertEqual(mark.status_code, 302)
        finalize = client.post(f"/attendance/meetings/{meeting_id}/finalize", data={
            "csrf_token": csrf
        })
        self.assertEqual(finalize.status_code, 302)
        with self.app.app_context():
            report = get_student_attendance_summary(student_id, selected_class_name="ENDTOEND101")
            self.assertEqual(report["present_count"], 1)
            self.assertEqual(report["absent_count"], 0)
            self.assertEqual(report["attendance_percentage"], 100.0)


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
