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

    def test_immediate_duplicate_scan_never_checks_out(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.services.scan_token_service import issue_access_credential
        with self.app.app_context():
            student = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
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

    def test_admin_dashboard_shows_population_presence_and_notices(self):
        client = self._signed_in_client()
        result = client.get("/admin/dashboard")
        self.assertEqual(result.status_code, 200)
        self.assertIn("Personas registradas por tipo".encode("utf-8"), result.data)
        self.assertIn("Monitor de usuarios".encode("utf-8"), result.data)
        self.assertIn("Dentro del campus".encode("utf-8"), result.data)
        self.assertIn("Avisos para la comunidad".encode("utf-8"), result.data)
        self.assertIn(b"StudentA", result.data)
        self.assertIn(b"TeacherA", result.data)
        self.assertIn(b"StaffA", result.data)
        self.assertNotIn("Clases y asistencia".encode("utf-8"), result.data)
        filtered = client.get("/admin/dashboard?monitor_role=estudiante&monitor_status=offline")
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
        self.assertIn("Solo alumnos".encode("utf-8"), student.get("/student/dashboard").data)
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
        self.assertIn("Solo docentes".encode("utf-8"), teacher.get("/professor/dashboard").data)
        self.assertNotIn("Solo docentes".encode("utf-8"), student.get("/student/dashboard").data)
        self.assertNotIn("Solo docentes".encode("utf-8"), worker.get("/personal/dashboard").data)
        with self.app.app_context():
            teacher_record = self.db.session.execute(
                self.db.select(UniversityNotice).where(UniversityNotice.title == "Solo docentes")
            ).scalar_one()
            teacher_record.is_active = False
            self.db.session.commit()

    def test_notice_form_protected_by_csrf(self):
        client = self._signed_in_client()
        response = client.post("/admin/notices/create", data={
            "title": "Missing CSRF", "body": "Should never be published", "audience": "all"
        })
        self.assertEqual(response.status_code, 400)

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

    def test_student_camera_and_code_verify_without_recording_entry(self):
        from app.models.user_model import User
        from app.models.access_log_model import AccessLog
        from app.models.scan_token_model import ScanToken
        from app.services.scan_token_service import issue_access_credential

        with self.app.app_context():
            student = self.db.session.execute(
                self.db.select(User).where(User.username == "StudentA")
            ).scalar_one()
            other = self.db.session.execute(
                self.db.select(User).where(User.username == "TeacherA")
            ).scalar_one()
            signed_qr, temporary_code = issue_access_credential(student)
            other_qr, _other_code = issue_access_credential(other)
            student_id = student.id
            old_count = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
            ).scalar_one()

        client = self._signed_in_client("StudentA")
        page = client.get("/student/access-control")
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(csrf)
        token = csrf.group(1).decode("utf-8")

        good_qr = client.post("/student/access-control", data={
            "qr_text": signed_qr, "csrf_token": token,
        })
        self.assertEqual(good_qr.status_code, 200)
        self.assertIn("Código verificado".encode("utf-8"), good_qr.data)

        good_code = client.post("/student/access-control", data={
            "pass_code": temporary_code, "csrf_token": token,
        })
        self.assertEqual(good_code.status_code, 200)
        self.assertIn("Código verificado".encode("utf-8"), good_code.data)

        wrong_user = client.post("/student/access-control", data={
            "qr_text": other_qr, "csrf_token": token,
        })
        self.assertEqual(wrong_user.status_code, 200)
        self.assertIn("Verificación rechazada".encode("utf-8"), wrong_user.data)

        with self.app.app_context():
            new_count = self.db.session.execute(
                self.db.select(self.db.func.count(AccessLog.id))
            ).scalar_one()
            self.assertEqual(old_count, new_count)
            still_live = self.db.session.execute(
                self.db.select(ScanToken).where(ScanToken.user_id == student_id)
                .order_by(ScanToken.id.desc())
            ).scalars().first()
            self.assertIsNotNone(still_live)
            self.assertIsNone(still_live.consumed_at)

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
        from app.services.scan_token_service import resolve_scan_token
        from app.models.user_model import User
        paths = [
            ("Admin", "/admin/access-control", "ADM"),
            ("StudentA", "/student/access-control", "EST"),
            ("TeacherA", "/professor/access-control", "DOC"),
            ("StaffA", "/personal/access-control", "PER"),
        ]
        issued = set()
        for username, path, expected_prefix in paths:
            with self.subTest(username=username):
                client = self._signed_in_client(username)
                page = client.get(path)
                self.assertEqual(page.status_code, 200)
                self.assertIn(b"data:image/png;base64,", page.data)
                matches = [
                    value for value in re.findall(
                        rb"(?:EST|DOC|PER|ADM)-(?:[A-HJ-NP-Z2-9]{4}-){3}[A-HJ-NP-Z2-9]{4}", page.data
                    )
                    if not value.endswith(b"XXXX-XXXX-XXXX-XXXX")
                ]
                self.assertTrue(matches, f"No generated temporary code on {path}")
                code = matches[0].decode("ascii")
                self.assertTrue(code.startswith(expected_prefix + "-"), code)
                self.assertNotIn(code, issued)
                issued.add(code)
                with self.app.app_context():
                    user, record = resolve_scan_token(code)
                    self.assertEqual(user.username, username)
                    self.assertIsNone(record.consumed_at)

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
