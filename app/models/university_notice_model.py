"""Institution-wide notices, targeted by recipient role and retained for auditing."""
from datetime import datetime
from app.database import db


class UniversityNotice(db.Model):
    __tablename__ = "university_notices"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # 'all', 'estudiante', 'docente', 'personal', or 'administrativo'.
    audience = db.Column(db.String(30), nullable=False, index=True)
    author_id = db.Column(db.Integer, nullable=False)
    author_name = db.Column(db.String(80), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    archived_at = db.Column(db.DateTime, nullable=True)
