"""Permanent university cards, approved QR rotation and temporary visitor passes."""
from datetime import timedelta
from pathlib import Path

from flask import Blueprint, abort, flash, redirect, render_template, request, send_file, url_for, jsonify
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


@credential_bp.route("/report", methods=["GET", "POST"])
@login_required
def report_issue():
    """Private authenticated support report; delivered to existing admin inbox."""
    if not current_user.is_active_user:
        abort(403)
    base = {
        "administrativo": "admin_base.html",
        "estudiante": "student_base.html",
        "docente": "professor_base.html",
        "personal": "personal_base.html",
        "visitante": "credential_visitor_base.html",
    }.get(current_user.role)
    if base is None:
        abort(403)
    if request.method == "POST":
        from app.models.contact_message_model import ContactMessage
        category = str(request.form.get("category", "")).strip().lower()
        subject = str(request.form.get("subject", "")).strip()
        description = str(request.form.get("description", "")).strip()
        if category not in {"soporte", "error", "consulta", "sugerencia"}:
            flash("Selecciona un tipo de reporte válido.", "error")
        elif not 5 <= len(subject) <= 120:
            flash("Escribe un asunto de entre 5 y 120 caracteres.", "error")
        elif not 10 <= len(description) <= 3000:
            flash("Describe el problema con entre 10 y 3000 caracteres.", "error")
        else:
            user_name = current_user.full_name() or current_user.username
            email = (current_user.email or "").strip()
            message = ContactMessage(
                name=user_name[:100],
                email=email[:160] or "sin-correo@unitrack.local",
                category=category,
                body=(
                    f"[Reporte de usuario autenticado: @{current_user.username}; "
                    f"rol: {current_user.role}; ID: {current_user.id}]\n"
                    f"Asunto: {subject}\n\n{description}"
                ),
            )
            from app.models.support_reply_model import SupportReportSender
            db.session.add(message)
            db.session.flush()
            db.session.add(SupportReportSender(
                report_id=message.id, user_id=current_user.id,
            ))
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                from flask import current_app
                current_app.logger.exception("Could not save authenticated user report")
                flash("No fue posible enviar el reporte. Intenta de nuevo.", "error")
            else:
                flash("Tu reporte se envió al administrador.", "success")
                return redirect(url_for("credential.report_issue"))
    return render_template(
        "credential_report.html", report_base=base, active_page="report"
    )


@credential_bp.route("/messages", methods=["GET"])
@login_required
def my_messages():
    """Private administrator replies, scoped to the current account only."""
    if not current_user.is_active_user:
        abort(403)
    base = {
        "administrativo": "admin_base.html",
        "estudiante": "student_base.html",
        "docente": "professor_base.html",
        "personal": "personal_base.html",
        "visitante": "credential_visitor_base.html",
    }.get(current_user.role)
    if not base:
        abort(403)
    from app.models.support_reply_model import SupportReply
    from app.models.contact_message_model import ContactMessage
    replies = db.session.execute(
        db.select(SupportReply, ContactMessage)
        .join(ContactMessage, SupportReply.report_id == ContactMessage.id)
        .where(SupportReply.recipient_user_id == current_user.id)
        .order_by(SupportReply.created_at.desc(), SupportReply.id.desc())
        .limit(100)
    ).all()
    from app.models.support_reply_model import SupportReportSender
    from app.models.support_conversation_model import SupportChatState
    from app.models.contact_message_model import ContactMessage
    conversations = db.session.execute(
        db.select(ContactMessage, SupportChatState)
        .join(SupportReportSender, SupportReportSender.report_id == ContactMessage.id)
        .outerjoin(SupportChatState, SupportChatState.report_id == ContactMessage.id)
        .where(SupportReportSender.user_id == current_user.id)
        .order_by(ContactMessage.created_at.desc(), ContactMessage.id.desc())
        .limit(100)
    ).all()
    return render_template(
        "credential_messages.html", inbox_base=base, replies=replies,
        conversations=conversations, active_page="messages"
    )


@credential_bp.route("/messages/<int:report_id>/updates", methods=["GET"])
@login_required
def support_chat_updates(report_id):
    """Authorized, no-cache updates for the currently open support thread."""
    if not current_user.is_active_user:
        abort(403)
    from app.services.support_chat_service import (
        load_conversation, conversation_items, mark_chat_read
    )
    report, sender, state = load_conversation(report_id)
    if report is None or sender is None:
        return jsonify({"deleted": True}), 404
    admin = _admin()
    if not admin and sender.user_id != current_user.id:
        abort(403)
    mark_chat_read(report_id, "admin" if admin else "reporter", current_user.id)
    items = conversation_items(report_id)
    response = jsonify({
        "closed": bool(state and state.closed_at),
        "messages": [{
            "key": item["kind"] + "-" + str(item["id"]),
            "sender": item["sender"],
            "body": item["body"],
            "when": item["when"].strftime("%Y-%m-%d %H:%M UTC") if item["when"] else "",
        } for item in items],
    })
    response.headers["Cache-Control"] = "private, no-store"
    return response


@credential_bp.route("/messages/<int:report_id>/chat", methods=["GET", "POST"])
@login_required
def my_support_chat(report_id):
    """Only the authenticated original sender can view or respond to a thread."""
    if not current_user.is_active_user:
        abort(403)
    from app.models.support_conversation_model import SupportChatMessage
    from app.services.support_chat_service import (
        load_conversation, conversation_items, mark_chat_read
    )
    report, sender, state = load_conversation(report_id)
    if report is None or sender is None:
        abort(404)
    if sender.user_id != current_user.id:
        abort(403)
    if request.method == "POST":
        if state and state.closed_at is not None:
            abort(409, description="Esta conversación está cerrada.")
        body = str(request.form.get("message", "")).strip()
        if not 1 <= len(body) <= 3000:
            flash("Escribe un mensaje de entre 1 y 3000 caracteres.", "error")
        else:
            db.session.add(SupportChatMessage(
                report_id=report_id,
                sender_user_id=current_user.id,
                body=body,
            ))
            db.session.commit()
            flash("Mensaje enviado al administrador.", "success")
            return redirect(url_for("credential.my_support_chat", report_id=report_id))
    mark_chat_read(report_id, "reporter", current_user.id)
    base = {
        "administrativo": "admin_base.html",
        "estudiante": "student_base.html",
        "docente": "professor_base.html",
        "personal": "personal_base.html",
        "visitante": "credential_visitor_base.html",
    }.get(current_user.role)
    if base is None:
        abort(403)
    return render_template(
        "support_chat.html", thread_base=base, active_page="messages",
        report=report, messages=conversation_items(report_id),
        closed=bool(state and state.closed_at), state=state, is_admin=False,
    )


@credential_bp.route("/messages/<int:reply_id>/read", methods=["POST"])
@login_required
def read_message(reply_id):
    """An account can acknowledge only messages addressed to itself."""
    if not current_user.is_active_user:
        abort(403)
    from datetime import datetime
    from app.models.support_reply_model import SupportReply
    reply = db.session.execute(db.select(SupportReply).where(
        SupportReply.id == reply_id,
        SupportReply.recipient_user_id == current_user.id,
    )).scalar_one_or_none()
    if reply is None:
        abort(404)
    if reply.read_at is None:
        reply.read_at = datetime.utcnow()
        db.session.commit()
    return redirect(url_for("credential.my_messages"))


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
    own_qr_requests = []
    if target.id == current_user.id:
        own_qr_requests = db.session.execute(
            db.select(CredentialReplacementRequest)
            .where(CredentialReplacementRequest.user_id == current_user.id)
            .order_by(CredentialReplacementRequest.requested_at.desc(),
                      CredentialReplacementRequest.id.desc())
            .limit(20)
        ).scalars().all()
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
                           own_qr_requests=own_qr_requests,
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
    # Preserve the existing pending-approval area and show a separate
    # chronological record of all decisions at the bottom of this page.
    qr_history = db.session.execute(
        db.select(CredentialReplacementRequest)
        .order_by(CredentialReplacementRequest.requested_at.desc(),
                  CredentialReplacementRequest.id.desc())
        .limit(200)
    ).scalars().all()
    visitor_requests = db.session.execute(db.select(VisitorRequest).where(
        VisitorRequest.status == "pending"
    ).order_by(VisitorRequest.id.desc())).scalars().all()
    passes = db.session.execute(db.select(VisitorPass).order_by(
        VisitorPass.id.desc()).limit(150)
    ).scalars().all()
    people = {u.id: u for u in db.session.execute(db.select(User)).scalars()}
    return render_template("credential_management.html", qr_requests=qr_requests,
                           qr_history=qr_history,
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
            review_replacement(request_id, current_user, decision == "approve")
            flash("Solicitud de QR revisada.", "success")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
        except Exception:
            db.session.rollback()
            from flask import current_app
            current_app.logger.exception("Failed recording QR replacement review audit")
            flash("No se pudo guardar la auditoría de aprobación.", "error")
    return redirect(url_for("credential.manage") + "#qr-replacement-history")


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
