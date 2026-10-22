import secrets
import hmac

from flask import Blueprint, current_app, flash, g, jsonify, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import ObjectDeletedError
from werkzeug.security import check_password_hash, generate_password_hash

from ..auth import login_required, login_user, logout_user, safe_redirect_target
from ..extensions import db, limiter
from ..models import User
from ..services.accounts import StaleAccountError, lock_account_identity, record_activity, reset_password
from ..services.captcha import verify_captcha
from ..services.email_verification import (
    EmailRateLimited, VerificationError, consume_email_verification, email_digest,
    issue_email_verification, normalize_email,
)
from ..services.mail import MailUnavailable
from ..services.password_transport import PasswordTransportError, decrypt_password_submission
from ..services.security import normalize_username, validate_registration


auth_bp = Blueprint("auth", __name__)


def _home_for_user(user=None):
    user = user or g.current_user
    return url_for("admin.admin_dashboard" if user.is_admin or user.is_staff else "user.inbox")


def _attach_email(user: User, digest: str) -> None:
    """DB uniqueness, not a count-then-insert check, enforces the three slots."""
    if user.email_hash == digest and user.email_slot:
        return
    for slot in range(1, 4):
        try:
            with db.session.begin_nested():
                user.email_hash, user.email_slot = digest, slot
                db.session.add(user)
                db.session.flush()
            return
        except IntegrityError:
            continue
    raise VerificationError("该邮箱已绑定 3 个账号，无法再添加账号。")


def _email_proof(purpose: str, target_auth_id: str | None = None) -> str:
    email = normalize_email(request.form.get("email", ""))
    consume_email_verification(
        request.form.get("email_challenge", ""), request.form.get("email_code", ""),
        email, purpose, target_auth_id,
    )
    return email_digest(email)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], methods=["POST"], per_method=True)
def login():
    if g.get("current_user"):
        return redirect(_home_for_user())
    if request.method == "POST":
        try:
            password, _ = decrypt_password_submission("login")
        except PasswordTransportError:
            flash("密码提交验证失败，请刷新页面后重试。", "error")
            return render_template("login.html"), 400
        username = normalize_username(request.form.get("username", ""))
        user = User.query.filter_by(username=username).first()
        candidate = user.password_hash if user else current_app.extensions["dummy_password_hash"]
        verified_identity = user.auth_id if user else None
        if check_password_hash(candidate, password) and user:
            try:
                valid = record_activity(user) and hmac.compare_digest(user.auth_id, verified_identity)
            except ObjectDeletedError:
                valid = False
            if not valid:
                flash("账号状态已变更，请重新登录。", "error")
                return render_template("login.html"), 400
            login_user(user, verified_auth_id=verified_identity)
            return redirect(safe_redirect_target(request.args.get("next")) or _home_for_user(user))
        flash("用户名或密码错误", "error")
    return render_template("login.html")


@auth_bp.route("/email-code", methods=["POST"])
@limiter.limit(lambda: current_app.config["EMAIL_SEND_RATE_LIMIT"], methods=["POST"])
def email_code():
    purpose = request.form.get("purpose", "")
    if purpose not in {"register", "reset", "bind_email"}:
        return jsonify(message="验证用途无效。"), 400
    if purpose == "bind_email" and not g.get("current_user"):
        return jsonify(message="请先登录。"), 401
    if not verify_captcha(request.form.get("captcha_id", ""), request.form.get("captcha_answer", "")):
        return jsonify(message="图片验证码错误或已过期，请刷新后重试。"), 400
    try:
        email = normalize_email(request.form.get("email", ""))
        target = None
        if purpose == "reset":
            username = normalize_username(request.form.get("username", ""))
            user = User.query.filter_by(username=username, email_hash=email_digest(email)).first()
            target = user.auth_id if user else secrets.token_hex(16)
        elif purpose == "bind_email":
            target = g.current_user.auth_id
        # Same delivery behavior whether or not the reset account matches.
        challenge_id = issue_email_verification(email, purpose, target)
    except EmailRateLimited as error:
        return jsonify(message=str(error)), 429
    except VerificationError as error:
        return jsonify(message=str(error)), 400
    except MailUnavailable as error:
        return jsonify(message=str(error)), 503
    return jsonify(
        id=challenge_id,
        message="验证码已发送，请检查邮箱。找回密码还需要邮箱与账号匹配。",
        resend_after=current_app.config["EMAIL_RESEND_SECONDS"],
    )


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["REGISTER_RATE_LIMIT"], methods=["POST"], per_method=True)
def register():
    if g.get("current_user"):
        return redirect(_home_for_user())
    if request.method == "POST":
        try:
            password, confirm = decrypt_password_submission("register")
            username = normalize_username(request.form.get("username", ""))
            errors = validate_registration(username=username, password=password, confirm=confirm,
                                           min_length=current_app.config["PASSWORD_MIN_LENGTH"])
            if errors:
                raise VerificationError("；".join(errors))
            if User.query.filter_by(username=username).first():
                raise VerificationError("该用户名已被使用。")
            digest = _email_proof("register")
            user = User(username=username, password_hash=generate_password_hash(password, method="scrypt"))
            _attach_email(user, digest)
            db.session.commit()
        except (VerificationError, PasswordTransportError) as error:
            db.session.rollback()
            flash(str(error), "error")
            return render_template("register.html"), 400
        except IntegrityError:
            db.session.rollback()
            flash("该用户名或邮箱名额已被使用，请重试。", "error")
            return render_template("register.html"), 409
        flash("注册成功，请登录", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"], per_method=True)
def forgot_password():
    if request.method == "POST":
        try:
            password, _ = decrypt_password_submission("reset")
            if len(password) < current_app.config["PASSWORD_MIN_LENGTH"]:
                raise VerificationError("新密码长度不足。")
            username = normalize_username(request.form.get("username", ""))
            digest = email_digest(normalize_email(request.form.get("email", "")))
            user = User.query.filter_by(username=username, email_hash=digest).first()
            _email_proof("reset", user.auth_id if user else secrets.token_hex(16))
            if not user:
                raise VerificationError("邮箱验证码无效或已过期，请重新获取。")
            reset_password(user, password)
            db.session.commit()
        except (VerificationError, PasswordTransportError, StaleAccountError):
            db.session.rollback()
            flash("重置失败，请检查账号、邮箱、验证码和新密码后重试。", "error")
            return render_template("forgot_password.html"), 400
        logout_user()
        flash("密码已重置，原有登录已失效，请重新登录。", "success")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html")


@auth_bp.route("/account/email", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute", methods=["POST"], per_method=True)
def account_email():
    if request.method == "POST":
        try:
            password, _ = decrypt_password_submission("bind_email")
            verified_identity = g.current_user.auth_id
            if not check_password_hash(g.current_user.password_hash, password):
                raise VerificationError("当前密码不正确。")
            lock_account_identity(g.current_user, expected_auth_id=verified_identity)
            digest = _email_proof("bind_email", verified_identity)
            _attach_email(g.current_user, digest)
            db.session.commit()
        except (VerificationError, PasswordTransportError, StaleAccountError) as error:
            db.session.rollback()
            flash(str(error), "error")
            return render_template("account_email.html"), 400
        flash("验证邮箱已更新。邮箱不会显示给店长或店员。", "success")
        return redirect(url_for("auth.account_email"))
    return render_template("account_email.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    return redirect(url_for("public.index"))
