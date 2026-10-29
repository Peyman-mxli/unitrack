"""Persist small, expiring counts of authentication attempts for abuse prevention."""
from datetime import datetime
from app.database import db


class AuthAttempt(db.Model):
    __tablename__ = "auth_attempts"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    action = db.Column(db.String(32), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
