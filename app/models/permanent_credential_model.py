"""Revocable, stable campus credentials for permanent university members.

Only a digest of the printed fallback code is stored. The actual QR and
fallback code are deterministically derived from the app SECRET_KEY and a
per-person generation. Existing student/access history remains unchanged.
"""
from datetime import datetime
from app.database import db


class PermanentCredential(db.Model):
    __tablename__ = "permanent_credentials"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    generation = db.Column(db.Integer, nullable=False, default=1)
    code_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    issued_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    replaced_at = db.Column(db.DateTime, nullable=True)


class CredentialReplacementRequest(db.Model):
    __tablename__ = "credential_replacement_requests"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    reason = db.Column(db.String(300), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    requested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
