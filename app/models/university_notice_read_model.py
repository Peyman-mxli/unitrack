"""Persistent per-recipient notice read receipts, independent of other accounts."""
from datetime import datetime

from app.database import db


class UniversityNoticeRead(db.Model):
    __tablename__ = "university_notice_reads"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    notice_id = db.Column(
        db.Integer, db.ForeignKey("university_notices.id"), primary_key=True
    )
    read_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
