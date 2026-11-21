"""Separate, time-limited visitor access, requests and visit history.

A registered visitor is a User with role 'visitante' and a linked pass.
An occasional visitor has no User account and is identified by the pass.
"""
from datetime import datetime
from app.database import db


class VisitorRequest(db.Model):
    __tablename__ = "visitor_access_requests"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    purpose = db.Column(db.String(300), nullable=False)
    desired_start = db.Column(db.DateTime, nullable=False)
    desired_end = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class VisitorPass(db.Model):
    __tablename__ = "visitor_passes"
    id = db.Column(db.Integer, primary_key=True)
    linked_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    full_name = db.Column(db.String(180), nullable=False)
    email = db.Column(db.String(160), nullable=True)
    purpose = db.Column(db.String(300), nullable=False)
    issued_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    nonce = db.Column(db.String(64), nullable=False, unique=True)
    starts_at = db.Column(db.DateTime, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class VisitorPassPhoto(db.Model):
    """Optional visitor portrait stored privately, separate from legacy pass rows.

    A dedicated table lets existing SQLite installations gain visitor photos via
    db.create_all(), without altering the visitor_passes table or old records.
    """
    __tablename__ = "visitor_pass_photos"
    pass_id = db.Column(db.Integer, db.ForeignKey("visitor_passes.id"), primary_key=True)
    photo_path = db.Column(db.String(255), nullable=False)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class VisitorAccessLog(db.Model):
    __tablename__ = "visitor_access_logs"
    id = db.Column(db.Integer, primary_key=True)
    pass_id = db.Column(db.Integer, db.ForeignKey("visitor_passes.id"), nullable=False, index=True)
    checked_in_at = db.Column(db.DateTime, nullable=False, index=True)
    checked_out_at = db.Column(db.DateTime, nullable=True)
