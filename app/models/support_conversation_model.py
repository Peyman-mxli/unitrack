"""Additive private two-way support conversation records.

Existing contact_messages, support_report_senders and support_replies are preserved.
"""
from datetime import datetime

from app.database import db


class SupportChatState(db.Model):
    __tablename__ = "support_chat_states"

    report_id = db.Column(
        db.Integer, db.ForeignKey("contact_messages.id"), primary_key=True
    )
    closed_at = db.Column(db.DateTime, nullable=True)
    closed_by_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )


class SupportChatMessage(db.Model):
    """Reporter messages; existing SupportReply remains for admin messages."""

    __tablename__ = "support_chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.Integer, db.ForeignKey("contact_messages.id"), nullable=False, index=True
    )
    sender_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, index=True
    )
    admin_read_at = db.Column(db.DateTime, nullable=True)
