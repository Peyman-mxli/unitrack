"""Isolated per-admin MFA credentials; migration-safe new tables."""
from datetime import datetime

from app.database import db


class AdminMFA(db.Model):
    __tablename__ = "admin_mfa"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    encrypted_secret = db.Column(db.String(512), nullable=False)
    enabled_at = db.Column(db.DateTime, nullable=True)
    last_counter = db.Column(db.BigInteger, nullable=False, default=-1)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AdminMFARecoveryCode(db.Model):
    __tablename__ = "admin_mfa_recovery_codes"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False, unique=True)
    used_at = db.Column(db.DateTime, nullable=True)
