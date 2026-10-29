"""Recent activity heartbeat for online status (not a permanent login claim)."""
from datetime import datetime
from app.database import db


class UserPresence(db.Model):
    __tablename__ = "user_presence"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
