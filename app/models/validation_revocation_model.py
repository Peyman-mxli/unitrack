"""Audit-friendly cancellation of issued validation codes."""
from datetime import datetime
from app.database import db


class ValidationCodeRevocation(db.Model):
    __tablename__ = "validation_code_revocations"
    id = db.Column(db.Integer, primary_key=True)
    code_id = db.Column(db.Integer, db.ForeignKey("validation_codes.id"), unique=True, nullable=False, index=True)
    revoked_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reason = db.Column(db.String(250))
