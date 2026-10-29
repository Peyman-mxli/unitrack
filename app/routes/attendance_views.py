"""Role-checked class scheduling and attendance tools for professors/admins."""
from datetime import datetime
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func

from app.database import db
from app.utils.local_time import campus_now
from app.models.user_model import User
from app.models.academic_models import (
    UniversityClass, ClassEnrollment, ClassMeeting, ClassAttendance,
)

attendance_bp = Blueprint("attendance", __name__, url_prefix="/attendance")


def _is_admin():
    return current_user.role == "administrativo"


def _is_teacher():
    return current_user.role == "docente"


def _can_manage(course):
    return _is_admin() or (_is_teacher() and course.professor_id == current_user.id)


def _require_manager():
    if not (_is_admin() or _is_teacher()):
        abort(403)


def _find_user(value):
    identifier = str(value or "").strip().lower()
    if not identifier:
        return None
    return db.session.execute(
        db.select(User).where(
            db.or_(func.lower(User.username) == identifier, func.lower(User.email) == identifier)
        )
    ).scalars().first()


@attendance_bp.route("/classes", methods=["GET"])
@login_required
def classes():
    _require_manager()
    query = db.select(UniversityClass).order_by(UniversityClass.code)
    if not _is_admin():
        query = query.where(UniversityClass.professor_id == current_user.id)
    courses = db.session.execute(query).scalars().all()
    return render_template(
        "attendance_classes.html", courses=courses, course=None,
        is_admin=_is_admin(), active_page="classes",
    )


@attendance_bp.route("/classes/create", methods=["POST"])
@login_required
def create_class():
    _require_manager()
    code = str(request.form.get("code", "")).strip().upper()
    title = str(request.form.get("title", "")).strip()
    professor = current_user
    if _is_admin():
        professor = _find_user(request.form.get("professor_username"))
    if not code or not title or not professor or professor.role != "docente":
        flash("Enter a class code, title and a valid professor.", "error")
        return redirect(url_for("attendance.classes"))
    if len(code) > 40 or len(title) > 160:
        abort(400)
    if db.session.execute(db.select(UniversityClass).where(UniversityClass.code == code)).scalar_one_or_none():
        flash("Class code already exists.", "error")
        return redirect(url_for("attendance.classes"))
    try:
        db.session.add(UniversityClass(
            code=code, title=title, professor_id=professor.id,
            room=str(request.form.get("room", "")).strip()[:80],
        ))
        db.session.commit()
        flash("Class created.", "success")
    except Exception:
        db.session.rollback()
        flash("Failed to create class.", "error")
    return redirect(url_for("attendance.classes"))


@attendance_bp.route("/classes/<int:class_id>", methods=["GET"])
@login_required
def class_detail(class_id):
    _require_manager()
    course = db.session.get(UniversityClass, class_id)
    if course is None:
        abort(404)
    if not _can_manage(course):
        abort(403)
    enrollment_rows = db.session.execute(
        db.select(ClassEnrollment, User)
        .join(User, User.id == ClassEnrollment.student_id)
        .where(ClassEnrollment.class_id == course.id)
        .order_by(User.last_name, User.first_name)
    ).all()
    meetings = db.session.execute(
        db.select(ClassMeeting).where(ClassMeeting.class_id == course.id)
        .order_by(ClassMeeting.starts_at.desc())
    ).scalars().all()
    attendance_by_meeting = {}
    if meetings:
        attendance_rows = db.session.execute(
            db.select(ClassAttendance).where(ClassAttendance.meeting_id.in_([m.id for m in meetings]))
        ).scalars().all()
        for entry in attendance_rows:
            attendance_by_meeting[(entry.meeting_id, entry.student_id)] = entry.status
    return render_template(
        "attendance_classes.html", courses=None, course=course,
        enrollment_rows=enrollment_rows, meetings=meetings,
        attendance_by_meeting=attendance_by_meeting,
        is_admin=_is_admin(), active_page="classes",
    )


@attendance_bp.route("/classes/<int:class_id>/enroll", methods=["POST"])
@login_required
def enroll(class_id):
    _require_manager()
    course = db.session.get(UniversityClass, class_id)
    if not course:
        abort(404)
    if not _can_manage(course):
        abort(403)
    student = _find_user(request.form.get("student_identifier"))
    if not student or student.role != "estudiante":
        flash("Enter a registered student username or email.", "error")
    elif db.session.execute(db.select(ClassEnrollment).where(
        ClassEnrollment.class_id == class_id, ClassEnrollment.student_id == student.id
    )).scalar_one_or_none():
        flash("Student is already enrolled.", "warning")
    else:
        try:
            db.session.add(ClassEnrollment(class_id=class_id, student_id=student.id))
            db.session.commit()
            flash("Student enrolled.", "success")
        except Exception:
            db.session.rollback()
            flash("Enrollment failed.", "error")
    return redirect(url_for("attendance.class_detail", class_id=class_id))


@attendance_bp.route("/classes/<int:class_id>/meeting", methods=["POST"])
@login_required
def add_meeting(class_id):
    _require_manager()
    course = db.session.get(UniversityClass, class_id)
    if not course:
        abort(404)
    if not _can_manage(course):
        abort(403)
    try:
        start = datetime.fromisoformat(str(request.form.get("starts_at") or ""))
        end = datetime.fromisoformat(str(request.form.get("ends_at") or ""))
        if end <= start:
            raise ValueError("End must follow start.")
        db.session.add(ClassMeeting(class_id=class_id, starts_at=start, ends_at=end))
        db.session.commit()
        flash("Meeting scheduled.", "success")
    except (ValueError, TypeError):
        flash("Enter valid meeting start and end times.", "error")
    except Exception:
        db.session.rollback()
        flash("Meeting could not be created.", "error")
    return redirect(url_for("attendance.class_detail", class_id=class_id))


@attendance_bp.route("/meetings/<int:meeting_id>/mark", methods=["POST"])
@login_required
def mark_attendance(meeting_id):
    _require_manager()
    meeting = db.session.get(ClassMeeting, meeting_id)
    if not meeting:
        abort(404)
    course = db.session.get(UniversityClass, meeting.class_id)
    if not _can_manage(course):
        abort(403)
    student_id = request.form.get("student_id", type=int)
    status = request.form.get("status", "")
    if status not in {"Present", "Late", "Absent"}:
        abort(400)
    enrollment = db.session.execute(
        db.select(ClassEnrollment).where(
            ClassEnrollment.class_id == course.id,
            ClassEnrollment.student_id == student_id,
        )
    ).scalar_one_or_none()
    if not enrollment or meeting.finalized_at:
        abort(400)
    # Do not mark a future class or a student who joined after the meeting.
    if campus_now() < meeting.starts_at or enrollment.enrolled_at > meeting.starts_at:
        abort(400)
    record = db.session.execute(
        db.select(ClassAttendance).where(
            ClassAttendance.meeting_id == meeting.id,
            ClassAttendance.student_id == student_id
        )
    ).scalar_one_or_none()
    if record is None:
        record = ClassAttendance(meeting_id=meeting.id, student_id=student_id,
                                 status=status, recorded_by=current_user.id)
        db.session.add(record)
    else:
        record.status = status
        record.recorded_by = current_user.id
        record.recorded_at = campus_now()
    db.session.commit()
    flash("Attendance saved.", "success")
    return redirect(url_for("attendance.class_detail", class_id=course.id))


@attendance_bp.route("/meetings/<int:meeting_id>/finalize", methods=["POST"])
@login_required
def finalize_meeting(meeting_id):
    _require_manager()
    meeting = db.session.get(ClassMeeting, meeting_id)
    if meeting is None:
        abort(404)
    course = db.session.get(UniversityClass, meeting.class_id)
    if not _can_manage(course):
        abort(403)
    if not meeting.finalized_at:
        if campus_now() < meeting.ends_at:
            flash("A meeting can only be finalized after it ends.", "error")
        else:
            # Materialize absences so student, professor and admin reports agree.
            enrolled = db.session.execute(
                db.select(ClassEnrollment).where(
                    ClassEnrollment.class_id == course.id,
                    ClassEnrollment.enrolled_at <= meeting.starts_at
                )
            ).scalars().all()
            marked_ids = set(db.session.execute(
                db.select(ClassAttendance.student_id).where(
                    ClassAttendance.meeting_id == meeting.id
                )
            ).scalars().all())
            for row in enrolled:
                if row.student_id not in marked_ids:
                    db.session.add(ClassAttendance(
                        meeting_id=meeting.id, student_id=row.student_id,
                        status="Absent", recorded_by=current_user.id
                    ))
            meeting.finalized_at = campus_now()
            db.session.commit()
            flash("Meeting finalized; unmarked enrolled students count as absent.", "success")
    return redirect(url_for("attendance.class_detail", class_id=course.id))
