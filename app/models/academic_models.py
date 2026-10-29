"""University classes, enrollment, scheduled meetings and attendance records."""
from datetime import datetime
from app.database import db


class UniversityClass(db.Model):
    __tablename__ = "university_classes"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(40), nullable=False, unique=True, index=True)
    title = db.Column(db.String(160), nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    room = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ClassEnrollment(db.Model):
    __tablename__ = "class_enrollments"
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey("university_classes.id"), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    enrolled_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("class_id", "student_id", name="uq_class_enrollment"),)


class ClassMeeting(db.Model):
    __tablename__ = "class_meetings"
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey("university_classes.id"), nullable=False, index=True)
    starts_at = db.Column(db.DateTime, nullable=False, index=True)
    ends_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    finalized_at = db.Column(db.DateTime, nullable=True)
    __table_args__ = (db.CheckConstraint("ends_at > starts_at", name="ck_meeting_end_after_start"),)


class ClassAttendance(db.Model):
    __tablename__ = "class_attendance"
    id = db.Column(db.Integer, primary_key=True)
    meeting_id = db.Column(db.Integer, db.ForeignKey("class_meetings.id"), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False)  # Present, Late, Absent
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint("meeting_id", "student_id", name="uq_class_attendance"),
        db.CheckConstraint("status IN ('Present', 'Late', 'Absent')", name="ck_attendance_status"),
    )
