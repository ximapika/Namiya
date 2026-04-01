from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from ..auth import login_user, logout_user, safe_redirect_target
from ..extensions import db, limiter
from ..models import User
from ..services.security import normalize_username, validate_registration


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["LOGIN_RATE_LIMIT"],
    methods=["POST"],
    per_method=True,
)
def login():
    if g.get("current_user"):
        if g.current_user.is_admin or g.current_user.is_staff:
            return redirect(url_for("admin.admin_dashboard"))
        return redirect(url_for("user.inbox"))

    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_url = safe_redirect_target(request.args.get("next"))
            if user.is_admin or user.is_staff:
                return redirect(next_url or url_for("admin.admin_dashboard"))
            return redirect(next_url or url_for("user.inbox"))

        flash("用户名或密码错误", "error")

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["REGISTER_RATE_LIMIT"],
    methods=["POST"],
    per_method=True,
)
def register():
    if g.get("current_user"):
        if g.current_user.is_admin or g.current_user.is_staff:
            return redirect(url_for("admin.admin_dashboard"))
        return redirect(url_for("user.inbox"))

    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = validate_registration(
            username=username,
            password=password,
            confirm=confirm,
            min_length=current_app.config["PASSWORD_MIN_LENGTH"],
        )

        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("register.html")

        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("该用户名已被使用", "error")
            return render_template("register.html")

        flash("注册成功，请登录", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("public.index"))
