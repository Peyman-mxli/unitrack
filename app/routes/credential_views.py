"""Permanent university cards, approved QR rotation and temporary visitor passes."""
from datetime import timedelta
from pathlib import Path

from flask import Blueprint, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from app.database import db
from app.models.user_model import User
from app.models.permanent_credential_model import CredentialReplacementRequest
from app.models.visitor_access_model import VisitorRequest, VisitorPass, VisitorAccessLog
from app.services.permanent_credential_service import (
    ROLES, permanent_credential_for_user, request_replacement, review_replacement
)
from app.services.visitor_access_service import (
    issue_visitor_pass, visitor_token, visitor_code,
    request_visitor_access, review_visitor_request,
)
from app.utils.local_time import campus_now

credential_bp = Blueprint("credential", __name__, url_prefix="/credentials")


def _admin():
    return current_user.is_authenticated and current_user.is_active_user and current_user.role == "administrativo"


@credential_bp.route("/card")
@credential_bp.route("/card/<int:user_id>")
@login_required
def card(user_id=None):
    target = current_user if user_id is None else db.session.get(User, user_id)
    if target is None:
        abort(404)
    if target.id != current_user.id and not _admin():
        abort(403)
    if target.role not in ROLES or not target.is_active_user:
        abort(403)
    from app.routes.student_views import generate_qr_image_data_uri, build_student_access_qr_payload
    token, manual_code = permanent_credential_for_user(target)
    qr_text = build_student_access_qr_payload(target, token=token)
    image = generate_qr_image_data_uri(qr_text)
    card_base = {
        "administrativo": "admin_base.html",
        "estudiante": "student_base.html",
        "docente": "professor_base.html",
        "personal": "personal_base.html",
    }.get(current_user.role)
    if not card_base:
        abort(403)
    return render_template("credential_card.html", card_base=card_base,
                           active_page="credential", person=target, qr_image=image,
                           code=manual_code, role_labels={
                               "estudiante": "ESTUDIANTE", "docente": "DOCENTE",
                               "personal": "PERSONAL", "administrativo": "ADMINISTRACIÓN"
                           }, can_manage=_admin())


@credential_bp.route("/photo/<int:user_id>")
@login_required
def photo(user_id):
    target = db.session.get(User, user_id)
    if target is None:
        abort(404)
    if target.id != current_user.id and not _admin():
        abort(403)
    raw = str(target.photo_path or "").replace("\\", "/").lstrip("/")
    root = Path(__file__).resolve().parents[2]
    prefixes = ("private_uploads/profile_photos/", "app/static/uploads/",
                "app/static/img/profiles/", "app/routes/static/uploads/")
    if not any(raw.startswith(prefix) for prefix in prefixes):
        abort(404)
    candidate = (root / raw).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        abort(404)
    return send_file(candidate, mimetype="image/jpeg")


@credential_bp.route("/request-replacement", methods=["POST"])
@login_required
def replacement_request():
    try:
        request_replacement(current_user, request.form.get("reason", ""))
        flash("Solicitud de cambio de QR enviada al administrador.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("credential.card"))


@credential_bp.route("/manage")
@login_required
def manage():
    if not _admin():
        abort(403)
    qr_requests = db.session.execute(db.select(CredentialReplacementRequest).where(
        CredentialReplacementRequest.status == "pending"
    ).order_by(CredentialReplacementRequest.id.desc())).scalars().all()
    visitor_requests = db.session.execute(db.select(VisitorRequest).where(
        VisitorRequest.status == "pending"
    ).order_by(VisitorRequest.id.desc())).scalars().all()
    passes = db.session.execute(db.select(VisitorPass).order_by(
        VisitorPass.id.desc()).limit(150)
    ).scalars().all()
    people = {u.id: u for u in db.session.execute(db.select(User)).scalars()}
    return render_template("credential_management.html", qr_requests=qr_requests,
                           visitor_requests=visitor_requests, passes=passes,
                           people=people, current_time=campus_now())


@credential_bp.route("/replacement/<int:request_id>/review", methods=["POST"])
@login_required
def review_qr(request_id):
    if not _admin():
        abort(403)
    decision = str(request.form.get("decision", "")).strip().lower()
    if decision not in {"approve", "reject"}:
        flash("Selecciona Aprobar o Rechazar.", "error")
    else:
        try:
            request_record = review_replacement(
                request_id, current_user, decision == "approve"
            )
            # The credential request itself stores the approver and timestamp.
            # Also add an administrator audit event for extra traceability.
            from app.models.admin_audit_model import AdminAuditLog
            target = db.session.get(User, request_record.user_id)
            db.session.add(AdminAuditLog(
                actor_id=current_user.id,
                actor_username=current_user.username,
                action="qr_replacement_" + request_record.status,
                target_user_id=request_record.user_id,
                target_username=target.username if target else None,
                details=f"QR replacement request #{request_record.id}: {request_record.status}",
            ))
            db.session.commit()
            flash("Solicitud de QR revisada.", "success")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
        except Exception:
            db.session.rollback()
            from flask import current_app
            current_app.logger.exception("Failed recording QR replacement review audit")
            flash("No se pudo guardar la auditoría de aprobación.", "error")
    return redirect(url_for("admin_views.admin_contact_messages") + "#qr-replacement-requests")


@credential_bp.route("/visitors/create", methods=["POST"])
@login_required
def create_guest():
    if not _admin():
        abort(403)
    try:
        duration = request.form.get("duration", "24")
        if duration in {"24", "48", "72"}:
            start = campus_now()
            end = start + timedelta(hours=int(duration))
        elif duration == "custom":
            start = request.form.get("starts_at", "")
            end = request.form.get("expires_at", "")
        else:
            raise ValueError("Select 24, 48, 72 hours or a custom date range.")
        item = issue_visitor_pass(
            current_user, request.form.get("full_name", ""),
            request.form.get("purpose", ""), start, end,
            email=request.form.get("email", ""),
        )
        flash(f"Visitor pass #{item.id} created.", "success")
        return redirect(url_for("credential.visitor_pass", pass_id=item.id))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("credential.manage"))


@credential_bp.route("/visitors/<int:pass_id>/revoke", methods=["POST"])
@login_required
def revoke_guest(pass_id):
    if not _admin():
        abort(403)
    item = db.session.get(VisitorPass, pass_id)
    if item is None:
        abort(404)
    item.revoked_at = campus_now()
    db.session.commit()
    flash("Visitante: acceso revocado.", "success")
    return redirect(url_for("credential.manage"))


@credential_bp.route("/visitor")
@login_required
def visitor():
    if current_user.role != "visitante":
        abort(403)
    requests = db.session.execute(db.select(VisitorRequest).where(
        VisitorRequest.user_id == current_user.id
    ).order_by(VisitorRequest.id.desc())).scalars().all()
    passes = db.session.execute(db.select(VisitorPass).where(
        VisitorPass.linked_user_id == current_user.id
    ).order_by(VisitorPass.id.desc())).scalars().all()
    return render_template("credential_visitor.html", requests=requests, passes=passes,
                           current_time=campus_now())


@credential_bp.route("/visitor/request", methods=["POST"])
@login_required
def visitor_request():
    if current_user.role != "visitante":
        abort(403)
    try:
        request_visitor_access(
            current_user, request.form.get("purpose", ""),
            request.form.get("starts_at", ""), request.form.get("expires_at", ""),
        )
        flash("Solicitud enviada. Un administrador revisará tu acceso.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("credential.visitor"))


@credential_bp.route("/visitor-request/<int:request_id>/review", methods=["POST"])
@login_required
def visitor_approval(request_id):
    if not _admin():
        abort(403)
    try:
        review_visitor_request(
            request_id, current_user, request.form.get("decision") == "approve",
            start=request.form.get("starts_at") or None,
            end=request.form.get("expires_at") or None,
        )
        flash("Solicitud de visitante revisada.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("credential.manage"))


@credential_bp.route("/visitor-pass/<int:pass_id>")
@login_required
def visitor_pass(pass_id):
    item = db.session.get(VisitorPass, pass_id)
    if item is None:
        abort(404)
    if not _admin() and (item.linked_user_id is None or item.linked_user_id != current_user.id):
        abort(403)
    from app.routes.student_views import generate_qr_image_data_uri
    token = visitor_token(item)
    qr_image = generate_qr_image_data_uri(token)
    history = db.session.execute(db.select(VisitorAccessLog).where(
        VisitorAccessLog.pass_id == item.id
    ).order_by(VisitorAccessLog.id.desc())).scalars().all()
    return render_template("credential_visitor_pass.html", item=item, qr_image=qr_image,
                           code=visitor_code(item), history=history, now=campus_now(),
                           can_manage=_admin())
