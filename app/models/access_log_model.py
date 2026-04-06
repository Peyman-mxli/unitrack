"""
access_log_model.py

Independent university access control model for UniTrack.

IMPORTANT:
This model is NOT the teacher attendance system.

Teacher attendance remains separate and untouched.

This model is only for:
- university entrance
- university exit
- QR access control
- student access history
- access hours calculation

One row = one university access record for one student.
"""

from datetime import datetime

from app.database import db


class AccessLog(db.Model):
    """
    University access control record for one student.

    This table stores:
    - who entered
    - when they checked in
    - when they checked out
    - how long they stayed
    - how the record was created
    """

    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    access_date = db.Column(
        db.Date,
        nullable=False,
        index=True,
        default=lambda: datetime.utcnow().date()
    )

    check_in_time = db.Column(
        db.DateTime,
        nullable=False,
        index=True,
        default=datetime.utcnow
    )

    check_out_time = db.Column(
        db.DateTime,
        nullable=True,
        index=True
    )

    access_status = db.Column(
        db.String(30),
        nullable=False,
        default="checked_in",
        index=True
    )
    # Expected values:
    # - checked_in
    # - checked_out

    access_method = db.Column(
        db.String(30),
        nullable=False,
        default="qr",
        index=True
    )
    # Expected values:
    # - qr
    # - manual
    # - admin

    notes = db.Column(
        db.String(255),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    student = db.relationship(
        "User",
        backref=db.backref("student_access_logs", lazy=True, cascade="all, delete-orphan")
    )

    def is_open(self):
        """
        Return True if the access log is still active.

        Active means:
        - check-in exists
        - check-out does not exist yet
        - status is checked_in
        """

        return self.check_in_time is not None and self.check_out_time is None

    def is_closed(self):
        """
        Return True if the access log has already been completed.
        """

        return self.check_in_time is not None and self.check_out_time is not None

    def calculate_duration(self):
        """
        Return the raw timedelta between check-in and check-out.

        If the log is still open or invalid,
        return None.
        """

        if not self.check_in_time or not self.check_out_time:
            return None

        delta = self.check_out_time - self.check_in_time

        if delta.total_seconds() < 0:
            return None

        return delta

    def calculate_minutes(self):
        """
        Return total completed minutes for this access log.

        If the log is still open or invalid,
        return 0.
        """

        duration = self.calculate_duration()

        if not duration:
            return 0

        total_seconds = int(duration.total_seconds())

        if total_seconds <= 0:
            return 0

        return total_seconds // 60

    def calculate_hours_decimal(self):
        """
        Return total duration in decimal hours.

        Example:
        90 minutes -> 1.50
        """

        total_minutes = self.calculate_minutes()

        if total_minutes <= 0:
            return 0.0

        return round(total_minutes / 60, 2)

    def calculate_hours(self):
        """
        Backward-compatible helper.

        Return raw timedelta between check-in and check-out.

        If the student has not checked out yet,
        return None.
        """

        return self.calculate_duration()

    def get_duration_text(self):
        """
        Return friendly duration text.

        Example:
        5h 25m

        If log is still open, return:
        En curso
        """

        if not self.check_in_time or not self.check_out_time:
            return "En curso"

        total_minutes = self.calculate_minutes()

        hours = total_minutes // 60
        minutes = total_minutes % 60

        return f"{hours}h {minutes}m"

    def mark_checked_out(self, check_out_time=None):
        """
        Close this access log safely.

        This helper updates:
        - check_out_time
        - access_status
        - updated_at
        """

        now = check_out_time or datetime.utcnow()

        self.check_out_time = now
        self.access_status = "checked_out"
        self.updated_at = now

    def __repr__(self):
        """
        Helpful for debugging and terminal testing.
        """
        return (
            f"<AccessLog "
            f"ID:{self.id} "
            f"Student:{self.student_id} "
            f"Date:{self.access_date} "
            f"Status:{self.access_status}>"
        )