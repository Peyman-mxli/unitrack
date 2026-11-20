"""Helpers for private, per-report support conversations."""
from datetime import datetime

from app.database import db
from app.models.contact_message_model import ContactMessage
from app.models.support_reply_model import SupportReply, SupportReportSender
from app.models.support_conversation_model import SupportChatMessage, SupportChatState


def load_conversation(report_id):
    report = db.session.get(ContactMessage, report_id)
    sender = db.session.get(SupportReportSender, report_id)
    if report is None or sender is None:
        return None, None, None
    return report, sender, db.session.get(SupportChatState, report_id)


def conversation_items(report_id):
    """Combine original report and legacy admin replies with reporter responses."""
    report = db.session.get(ContactMessage, report_id)
    if report is None:
        return []
    result = [
        {
            "kind": "report",
            "sender": "reporter",
            "body": report.body,
            "when": report.created_at,
            "id": 0,
        }
    ]
    for item in db.session.execute(
        db.select(SupportReply)
        .where(SupportReply.report_id == report_id)
        .order_by(SupportReply.created_at, SupportReply.id)
    ).scalars():
        result.append({
            "kind": "reply", "sender": "admin", "body": item.message,
            "when": item.created_at, "id": item.id,
        })
    for item in db.session.execute(
        db.select(SupportChatMessage)
        .where(SupportChatMessage.report_id == report_id)
        .order_by(SupportChatMessage.created_at, SupportChatMessage.id)
    ).scalars():
        result.append({
            "kind": "chat", "sender": "reporter", "body": item.body,
            "when": item.created_at, "id": item.id,
        })
    return sorted(result, key=lambda item: (
        item["when"] or datetime.min,
        0 if item["kind"] == "report" else 1,
        item["id"],
    ))


def mark_chat_read(report_id, reader_role, reader_id=None):
    """Mark delivered messages read only by their intended receiver."""
    now = datetime.utcnow()
    changed = False
    if reader_role == "admin":
        rows = db.session.execute(db.select(SupportChatMessage).where(
            SupportChatMessage.report_id == report_id,
            SupportChatMessage.admin_read_at.is_(None),
        )).scalars().all()
        for row in rows:
            row.admin_read_at = now
            changed = True
        report = db.session.get(ContactMessage, report_id)
        if report is not None and report.status == "new":
            report.status = "reviewed"
            report.reviewed_at = now
            changed = True
    elif reader_role == "reporter":
        rows = db.session.execute(db.select(SupportReply).where(
            SupportReply.report_id == report_id,
            SupportReply.recipient_user_id == reader_id,
            SupportReply.read_at.is_(None),
        )).scalars().all()
        for row in rows:
            row.read_at = now
            changed = True
    if changed:
        db.session.commit()
