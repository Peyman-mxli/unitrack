"""Persistent per-account login failure counters and one-use email approval tokens."""
from datetime import datetime
from app.database import db


class LoginSecurityState(db.Model):
    __tablename__ = "login_security_states"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    unlock_token_hash = db.Column(db.String(64), unique=True, index=True, nullable=True)
    unlock_expires_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
