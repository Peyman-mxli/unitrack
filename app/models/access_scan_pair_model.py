"""Pair a signed QR credential with one campus entry and its eventual exit.

New table only: no alterations to existing user, token, or attendance records.
"""
from datetime import datetime
from app.database import db


class AccessScanPair(db.Model):
    __tablename__ = "access_scan_pairs"

    id = db.Column(db.Integer, primary_key=True)
    scan_token_id = db.Column(
        db.Integer, db.ForeignKey("scan_tokens.id"), unique=True, nullable=False, index=True
    )
    access_log_id = db.Column(
        db.Integer, db.ForeignKey("access_logs.id"), unique=True, nullable=False, index=True
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    checked_in_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    checked_out_at = db.Column(db.DateTime, nullable=True)
