"""Academic attendance reporting based on enrolled, scheduled class meetings.

Campus access logs are intentionally NOT treated as classroom attendance.
Unmarked meetings count as absences only after a teacher finalizes them.
"""
from datetime import datetime, date
from sqlalchemy import and_
from app.database import db
from app.models.user_model import User
from app.models.academic_models import (
    UniversityClass, ClassEnrollment, ClassMeeting, ClassAttendance,
)


def _attendance_rows(student_id, selected_date="", selected_class_name=""):
    try:
        requested_date = date.fromisoformat(selected_date) if selected_date else None
    except ValueError:
        requested_date = None

    query = (
        db.select(ClassMeeting, UniversityClass, ClassAttendance, User, ClassEnrollment)
        .join(UniversityClass, ClassMeeting.class_id == UniversityClass.id)
        .join(ClassEnrollment, and_(
            ClassEnrollment.class_id == UniversityClass.id,
            ClassEnrollment.student_id == student_id,
        ))
        .join(User, User.id == UniversityClass.professor_id)
        .outerjoin(ClassAttendance, and_(
            ClassAttendance.meeting_id == ClassMeeting.id,
            ClassAttendance.student_id == student_id,
        ))
        .order_by(ClassMeeting.starts_at.desc())
    )
    if selected_class_name:
        query = query.where(UniversityClass.code == selected_class_name)
    results = db.session.execute(query).all()
    now = datetime.utcnow()
    rows = []
    for meeting, course, attendance, professor, enrollment in results:
        if meeting.starts_at < enrollment.enrolled_at:
            continue
        if requested_date and meeting.starts_at.date() != requested_date:
            continue
        if attendance:
            status = attendance.status
        elif meeting.finalized_at is not None:
            status = "Absent"
        else:
            # Unfinalized sessions are not marked absent or present.
            continue
        rows.append({
            "row": len(rows) + 1,
            "date": meeting.starts_at.strftime("%m/%d/%Y"),
            "time": meeting.starts_at.strftime("%I:%M %p"),
            "class_display_name": course.title,
            "class_name": course.code,
            "teacher_name": f"{professor.first_name} {professor.last_name}".strip(),
            "status": status,
        })
    return rows


def build_student_attendance_history_rows(student_id, selected_date="", selected_class_name=""):
    return _attendance_rows(student_id, selected_date, selected_class_name)


def get_student_attendance_class_options(student_id):
    stmt = (
        db.select(UniversityClass.code)
        .join(ClassEnrollment, ClassEnrollment.class_id == UniversityClass.id)
        .where(ClassEnrollment.student_id == student_id)
        .order_by(UniversityClass.code)
    )
    return db.session.execute(stmt).scalars().all()


def get_student_attendance_summary(student_id, selected_date="", selected_class_name=""):
    rows = _attendance_rows(student_id, selected_date, selected_class_name)
    present = sum(r["status"] == "Present" for r in rows)
    late = sum(r["status"] == "Late" for r in rows)
    absent = sum(r["status"] == "Absent" for r in rows)
    total = present + late + absent
    percentage = round(100 * (present + late) / total, 1) if total else 0
    return {
        "attendance_percentage": percentage,
        "attendance_percentage_color": "green" if percentage >= 80 else "yellow" if percentage >= 60 else "red",
        "present_count": present,
        "late_count": late,
        "absent_count": absent,
    }
