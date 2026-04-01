from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

from ..auth import admin_required, staff_or_admin_required
from ..extensions import db, limiter
from ..models import Letter, Reply, ReplyRequest, User
from ..services.security import normalize_username, validate_reply_content


admin_bp = Blueprint("admin", __name__)


def _reply_count_subquery():
    return (
        db.session.query(
            Reply.letter_id.label("letter_id"),
            func.count(Reply.id).label("reply_count"),
        )
        .group_by(Reply.letter_id)
        .subquery()
    )


@admin_bp.route("/admin")
@staff_or_admin_required
def admin_dashboard():
    filter_status = request.args.get("status", "all")
    filter_type = request.args.get("type", "all")
    search_user = request.args.get("search", "").strip()

    reply_counts = _reply_count_subquery()
    query = (
        db.session.query(Letter, reply_counts.c.reply_count)
        .options(joinedload(Letter.user))
        .outerjoin(reply_counts, Letter.id == reply_counts.c.letter_id)
    )

    if filter_type in {"letter", "phone"}:
        query = query.filter(Letter.type == filter_type)

    if search_user:
        query = query.join(User, Letter.user_id == User.id).filter(User.username.ilike(f"%{search_user}%"))

    letter_rows = query.order_by(Letter.created_at.desc()).all()
    letters = []
    for letter, reply_count in letter_rows:
        letter.reply_count = int(reply_count or 0)
        letter.username = letter.user.username
        letters.append(letter)

    if filter_status == "pending":
        letters = [item for item in letters if item.reply_count == 0]
    elif filter_status == "replied":
        letters = [item for item in letters if item.reply_count > 0]

    total = db.session.query(func.count(Letter.id)).scalar() or 0
    total_letter = db.session.query(func.count(Letter.id)).filter(Letter.type == "letter").scalar() or 0
    total_phone = db.session.query(func.count(Letter.id)).filter(Letter.type == "phone").scalar() or 0
    pending = (
        db.session.query(func.count(Letter.id))
        .outerjoin(reply_counts, Letter.id == reply_counts.c.letter_id)
        .filter(reply_counts.c.reply_count.is_(None))
        .scalar()
        or 0
    )
    replied = total - pending

    pending_requests = []
    if g.current_user.is_admin:
        pending_requests = (
            db.session.query(
                ReplyRequest.id,
                ReplyRequest.letter_id,
                ReplyRequest.created_at,
                Letter.title.label("letter_title"),
                User.username.label("staff_name"),
            )
            .join(Letter, ReplyRequest.letter_id == Letter.id)
            .join(User, ReplyRequest.staff_id == User.id)
            .filter(ReplyRequest.status == "pending")
            .order_by(ReplyRequest.created_at.asc())
            .all()
        )

    return render_template(
        "admin.html",
        letters=letters,
        total=total,
        total_letter=total_letter,
        total_phone=total_phone,
        pending=pending,
        replied=replied,
        filter_status=filter_status,
        filter_type=filter_type,
        search_user=search_user,
        pending_requests=pending_requests,
    )


@admin_bp.route("/admin/letter/<int:letter_id>", methods=["GET", "POST"])
@staff_or_admin_required
@limiter.limit(
    lambda: current_app.config["ADMIN_MUTATION_RATE_LIMIT"],
    methods=["POST"],
    per_method=True,
)
def admin_letter(letter_id: int):
    letter = Letter.query.options(joinedload(Letter.user)).filter(Letter.id == letter_id).first()

    if not letter:
        flash("信件不存在", "error")
        return redirect(url_for("admin.admin_dashboard"))

    letter.username = letter.user.username

    can_reply = bool(g.current_user.is_admin)
    approved_request = None
    if g.current_user.is_staff and not g.current_user.is_admin:
        approved_request = ReplyRequest.query.filter_by(
            letter_id=letter_id,
            staff_id=g.current_user.id,
            status="approved",
        ).first()
        can_reply = bool(approved_request)

    has_pending_request = False
    if g.current_user.is_staff and not g.current_user.is_admin:
        has_pending_request = ReplyRequest.query.filter_by(
            letter_id=letter_id,
            staff_id=g.current_user.id,
            status="pending",
        ).first() is not None

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "reply":
            if not can_reply:
                flash("您没有回复此信件的权限", "error")
            else:
                errors, clean_content = validate_reply_content(request.form.get("content", ""))
                if errors:
                    for err in errors:
                        flash(err, "error")
                else:
                    reply = Reply(letter_id=letter_id, admin_id=g.current_user.id, content=clean_content)
                    db.session.add(reply)
                    db.session.commit()
                    flash("回信已发送", "success")
                    return redirect(url_for("admin.admin_letter", letter_id=letter_id))

        elif action == "request_reply":
            if g.current_user.is_admin:
                flash("店长无需申请权限", "info")
            elif has_pending_request:
                flash("已提交申请，请等待店长审批", "info")
            elif approved_request:
                flash("您已拥有该信件的回复权限", "info")
            else:
                req = ReplyRequest(letter_id=letter_id, staff_id=g.current_user.id, status="pending")
                db.session.add(req)
                try:
                    db.session.commit()
                    flash("已向店长申请回复权限，请等待审批", "success")
                except IntegrityError:
                    db.session.rollback()
                    flash("该信件已有您的权限记录，请刷新后重试", "warning")
                return redirect(url_for("admin.admin_letter", letter_id=letter_id))

    replies = (
        db.session.query(
            Reply.content,
            Reply.created_at,
            User.username.label("admin_name"),
        )
        .join(User, Reply.admin_id == User.id)
        .filter(Reply.letter_id == letter_id)
        .order_by(Reply.created_at.asc())
        .all()
    )

    reply_counts = _reply_count_subquery()
    history_rows = (
        db.session.query(Letter, reply_counts.c.reply_count)
        .outerjoin(reply_counts, Letter.id == reply_counts.c.letter_id)
        .filter(Letter.user_id == letter.user_id, Letter.id != letter_id)
        .order_by(Letter.created_at.desc())
        .all()
    )
    user_history = []
    for history_letter, reply_count in history_rows:
        history_letter.reply_count = int(reply_count or 0)
        user_history.append(history_letter)

    return render_template(
        "admin_letter.html",
        letter=letter,
        replies=replies,
        can_reply=can_reply,
        has_pending_request=has_pending_request,
        user_history=user_history,
    )


@admin_bp.route("/admin/approve_reply/<int:req_id>", methods=["POST"])
@admin_required
@limiter.limit("20 per minute", methods=["POST"], per_method=True)
def approve_reply(req_id: int):
    action = request.form.get("action", "approve")
    req = db.session.get(ReplyRequest, req_id)
    if not req:
        flash("申请不存在", "warning")
        return redirect(url_for("admin.admin_dashboard"))

    req.status = "approved" if action == "approve" else "rejected"
    db.session.commit()
    if req.status == "approved":
        flash("已批准回复申请", "success")
    else:
        flash("已拒绝回复申请", "info")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/admin/staff")
@admin_required
def admin_staff():
    search_user = request.args.get("search", "").strip()

    staff_list = (
        User.query.filter_by(is_staff=True, is_admin=False)
        .order_by(User.username.asc())
        .all()
    )

    search_result = None
    search_history = []
    if search_user:
        search_result = User.query.filter_by(username=search_user).first()
        if search_result:
            reply_counts = _reply_count_subquery()
            search_rows = (
                db.session.query(Letter, reply_counts.c.reply_count)
                .outerjoin(reply_counts, Letter.id == reply_counts.c.letter_id)
                .filter(Letter.user_id == search_result.id)
                .order_by(Letter.created_at.desc())
                .all()
            )
            search_history = []
            for letter, reply_count in search_rows:
                letter.reply_count = int(reply_count or 0)
                search_history.append(letter)

    return render_template(
        "admin_staff.html",
        staff_list=staff_list,
        search_user=search_user,
        search_result=search_result,
        search_history=search_history,
    )


@admin_bp.route("/admin/grant_staff", methods=["POST"])
@admin_required
@limiter.limit("20 per minute", methods=["POST"], per_method=True)
def grant_staff():
    username = normalize_username(request.form.get("username", ""))
    action = request.form.get("action", "grant")
    redirect_to = request.form.get("redirect_to", "staff")

    user = User.query.filter_by(username=username).first()
    if not user:
        flash(f'用户 "{username}" 不存在', "error")
    elif user.is_admin:
        flash("该账号已是店长，无需授予店员权限", "info")
    else:
        user.is_staff = action == "grant"
        db.session.commit()
        if user.is_staff:
            flash(f"已授予 {username} 店员权限", "success")
        else:
            flash(f"已撤销 {username} 的店员权限", "success")

    if redirect_to == "dashboard":
        return redirect(url_for("admin.admin_dashboard"))
    return redirect(url_for("admin.admin_staff", search=username))


@admin_bp.route("/admin/grant_reply_direct/<int:letter_id>", methods=["POST"])
@admin_required
@limiter.limit("20 per minute", methods=["POST"], per_method=True)
def grant_reply_direct(letter_id: int):
    staff_username = normalize_username(request.form.get("staff_username", ""))
    staff = User.query.filter_by(username=staff_username, is_staff=True, is_admin=False).first()
    if not staff:
        flash(f'店员 "{staff_username}" 不存在', "error")
        return redirect(url_for("admin.admin_letter", letter_id=letter_id))

    existing = ReplyRequest.query.filter_by(letter_id=letter_id, staff_id=staff.id).first()
    if existing:
        if existing.status == "approved":
            flash(f"{staff_username} 已拥有此信件的回复权限", "info")
        else:
            existing.status = "approved"
            db.session.commit()
            flash(f"已直接授予 {staff_username} 对此信件的回复权限", "success")
    else:
        record = ReplyRequest(letter_id=letter_id, staff_id=staff.id, status="approved")
        db.session.add(record)
        try:
            db.session.commit()
            flash(f"已直接授予 {staff_username} 对此信件的回复权限", "success")
        except IntegrityError:
            db.session.rollback()
            flash("授权状态已被其他请求更新，请刷新后重试", "warning")

    return redirect(url_for("admin.admin_letter", letter_id=letter_id))
