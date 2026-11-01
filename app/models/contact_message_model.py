"""Public landing-page contact and bug reports, readable only by UniTrack admins."""
from datetime import datetime
from app.database import db


class ContactMessage(db.Model):
    __tablename__ = "contact_messages"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(160), nullable=False)
    category = db.Column(db.String(24), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="new", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<ContactMessage {self.id} {self.category} {self.status}>"
