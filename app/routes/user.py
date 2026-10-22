from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func, select
from sqlalchemy.orm import load_only

from ..auth import login_required
from ..extensions import db, limiter
from ..models import Letter, Reply, User
from ..services.security import validate_letter_submission
from ..services.pagination import paginate
from ..services.quotas import consume_daily_message
from ..services.rate_limits import user_rate_key


user_bp = Blueprint("user", __name__)


def _reply_count_column():
    return (
        select(func.count(Reply.id)).where(Reply.letter_id == Letter.id)
        .correlate(Letter).scalar_subquery().label("reply_count")
    )


@user_bp.route("/write", methods=["GET", "POST"])
@login_required
@limiter.limit(
    lambda: current_app.config["WRITE_RATE_LIMIT"],
    methods=["POST"],
    per_method=True,
    key_func=user_rate_key,
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

        if not consume_daily_message(g.current_user):
            db.session.rollback()
            flash("今天的来信和来电登记次数已用完，请明天再来", "error")
            return render_template("write.html"), 429

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

    pagination = paginate(
        db.session.query(Letter, _reply_count_column())
        .options(load_only(Letter.id, Letter.title, Letter.type, Letter.created_at,
                           Letter.preferred_call_time_raw))
        .filter(Letter.user_id == g.current_user.id)
        .order_by(Letter.created_at.desc(), Letter.id.desc())
    )
    letters = []
    for letter, reply_count in pagination.items:
        letter.reply_count = int(reply_count or 0)
        letters.append(letter)

    return render_template("inbox.html", letters=letters, pagination=pagination)


@user_bp.route("/letter/<int:letter_id>")
@login_required
def view_letter(letter_id: int):
    if g.current_user.is_admin or g.current_user.is_staff:
        return redirect(url_for("admin.admin_letter", letter_id=letter_id))

    letter = Letter.query.filter_by(id=letter_id, user_id=g.current_user.id).first()
    if not letter:
        flash("信件不存在或无权访问", "error")
        return redirect(url_for("user.inbox"))

    replies_page = paginate(
        db.session.query(
            Reply.content,
            Reply.created_at,
            User.username.label("admin_name"),
        )
        .join(User, Reply.admin_id == User.id)
        .filter(Reply.letter_id == letter_id)
        .order_by(Reply.created_at.asc(), Reply.id.asc()), parameter="reply_page"
    )

    return render_template("view_letter.html", letter=letter, replies=replies_page.items,
                           replies_page=replies_page)
