from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func

from ..auth import login_required
from ..extensions import db, limiter
from ..models import Letter, Reply, User
from ..services.security import validate_letter_submission


user_bp = Blueprint("user", __name__)


def _reply_count_subquery():
    return (
        db.session.query(
            Reply.letter_id.label("letter_id"),
            func.count(Reply.id).label("reply_count"),
        )
        .group_by(Reply.letter_id)
        .subquery()
    )


@user_bp.route("/write", methods=["GET", "POST"])
@login_required
@limiter.limit(
    lambda: current_app.config["WRITE_RATE_LIMIT"],
    methods=["POST"],
    per_method=True,
)
def write():
    if g.current_user.is_admin or g.current_user.is_staff:
        return redirect(url_for("admin.admin_dashboard"))

    if request.method == "POST":
        errors, payload = validate_letter_submission(request.form)
        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("write.html")

        letter = Letter(
            user_id=g.current_user.id,
            title=payload["title"],
            content=payload["content"],
            type=payload["type"],
        )
        if payload["type"] == "phone":
            letter.phone_number = payload["phone_number"]
            letter.preferred_call_time = payload["preferred_call_time"]

        db.session.add(letter)
        db.session.commit()

        if payload["type"] == "phone":
            flash("您的来电登记已成功提交，店员将尽快与您联系", "success")
        else:
            flash("您的信已成功送出，请等待店员回复", "success")
        return redirect(url_for("user.inbox"))

    return render_template("write.html")


@user_bp.route("/inbox")
@login_required
def inbox():
    if g.current_user.is_admin or g.current_user.is_staff:
        return redirect(url_for("admin.admin_dashboard"))

    reply_counts = _reply_count_subquery()
    letter_rows = (
        db.session.query(Letter, reply_counts.c.reply_count)
        .outerjoin(reply_counts, Letter.id == reply_counts.c.letter_id)
        .filter(Letter.user_id == g.current_user.id)
        .order_by(Letter.created_at.desc())
        .all()
    )
    letters = []
    for letter, reply_count in letter_rows:
        letter.reply_count = int(reply_count or 0)
        letters.append(letter)

    return render_template("inbox.html", letters=letters)


@user_bp.route("/letter/<int:letter_id>")
@login_required
def view_letter(letter_id: int):
    if g.current_user.is_admin or g.current_user.is_staff:
        return redirect(url_for("admin.admin_letter", letter_id=letter_id))

    letter = Letter.query.filter_by(id=letter_id, user_id=g.current_user.id).first()
    if not letter:
        flash("信件不存在或无权访问", "error")
        return redirect(url_for("user.inbox"))

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

    return render_template("view_letter.html", letter=letter, replies=replies)
