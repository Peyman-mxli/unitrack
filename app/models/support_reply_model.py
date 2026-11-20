"""Private replies from administrators to signed-in report senders."""
from datetime import datetime

from app.database import db


class SupportReply(db.Model):
    __tablename__ = "support_replies"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("contact_messages.id"), nullable=False, index=True)
    recipient_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime, nullable=True)
