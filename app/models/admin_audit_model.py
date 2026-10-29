"""Persistent record of administrator actions (never stores passwords or secrets)."""
from datetime import datetime
from app.database import db


class AdminAuditLog(db.Model):
    __tablename__ = "admin_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, nullable=False, index=True)
    actor_username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(60), nullable=False, index=True)
    target_user_id = db.Column(db.Integer, nullable=True, index=True)
    target_username = db.Column(db.String(80), nullable=True)
    details = db.Column(db.String(250), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
