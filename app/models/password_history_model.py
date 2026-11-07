"""Only non-reversible password hashes are retained, never plaintext passwords."""
from datetime import datetime
from app.database import db


class PasswordHistory(db.Model):
    __tablename__ = "password_history"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
