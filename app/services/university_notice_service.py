"""Role-scoped in-app university notice inbox and read state."""
from datetime import datetime

from app.database import db
from app.models.university_notice_model import UniversityNotice
from app.models.university_notice_read_model import UniversityNoticeRead

INBOX_ROLES = frozenset(("estudiante", "docente", "personal"))


def can_access_inbox(user):
    return bool(
        user and getattr(user, "is_authenticated", False)
        and getattr(user, "is_active_user", False)
        and getattr(user, "role", None) in INBOX_ROLES
    )


def visible_notice_query(user):
    """An announcement must be active and addressed to this user's role."""
    return db.select(UniversityNotice).where(
        UniversityNotice.is_active.is_(True),
        UniversityNotice.audience.in_(("all", user.role)),
    )


def read_ids_for_user(user, notice_ids):
    if not notice_ids:
        return set()
    return set(db.session.execute(
        db.select(UniversityNoticeRead.notice_id).where(
            UniversityNoticeRead.user_id == user.id,
            UniversityNoticeRead.notice_id.in_(notice_ids),
        )
    ).scalars().all())


def unread_notice_count(user):
    if not can_access_inbox(user):
        return 0
    read_subquery = db.select(UniversityNoticeRead.notice_id).where(
        UniversityNoticeRead.user_id == user.id
    )
    return db.session.execute(
        db.select(db.func.count(UniversityNotice.id))
        .where(
            UniversityNotice.is_active.is_(True),
            UniversityNotice.audience.in_(("all", user.role)),
            UniversityNotice.id.not_in(read_subquery),
        )
    ).scalar_one()


def inbox_page(user, page=1, per_page=15):
    """Paginated history of active announcements addressed to this person."""
    if not can_access_inbox(user):
        raise PermissionError("Inbox is not available to this account.")
    page = max(1, int(page))
    rows = db.paginate(
        visible_notice_query(user).order_by(
            UniversityNotice.created_at.desc(), UniversityNotice.id.desc()
        ),
        page=page, per_page=per_page, error_out=False,
    )
    return rows, read_ids_for_user(user, [notice.id for notice in rows.items])


def mark_notice_read(user, notice_id):
    """Idempotent, role-checked read receipt; cannot read another role's notice."""
    if not can_access_inbox(user):
        raise PermissionError("Inbox is not available to this account.")
    notice = db.session.execute(
        visible_notice_query(user).where(UniversityNotice.id == notice_id)
    ).scalar_one_or_none()
    if notice is None:
        return False
    receipt = db.session.get(UniversityNoticeRead, (user.id, notice.id))
    if receipt is None:
        db.session.add(UniversityNoticeRead(
            user_id=user.id, notice_id=notice.id, read_at=datetime.utcnow()
        ))
        db.session.commit()
    return True


def mark_all_notices_read(user):
    """Mark only CURRENTLY accessible, active announcements as read."""
    if not can_access_inbox(user):
        raise PermissionError("Inbox is not available to this account.")
    visible_ids = db.session.execute(
        visible_notice_query(user).with_only_columns(UniversityNotice.id)
    ).scalars().all()
    existing = read_ids_for_user(user, visible_ids)
    for notice_id in visible_ids:
        if notice_id not in existing:
            db.session.add(UniversityNoticeRead(
                user_id=user.id, notice_id=notice_id
            ))
    db.session.commit()
    return len(visible_ids) - len(existing)
