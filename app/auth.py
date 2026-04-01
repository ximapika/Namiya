from collections.abc import Callable
from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import flash, g, redirect, request, session, url_for


def sync_session_from_user(user, preserve_theme: bool = True) -> None:
    theme_name = session.get("theme_name") if preserve_theme else None
    session["user_id"] = user.id
    session["username"] = user.username
    session["is_admin"] = bool(user.is_admin)
    session["is_staff"] = bool(user.is_staff)
    session.permanent = True
    if theme_name:
        session["theme_name"] = theme_name


def login_user(user) -> None:
    theme_name = session.get("theme_name")
    session.clear()
    if theme_name:
        session["theme_name"] = theme_name
    sync_session_from_user(user, preserve_theme=True)


def logout_user() -> None:
    theme_name = session.get("theme_name")
    session.clear()
    if theme_name:
        session["theme_name"] = theme_name


def _redirect_to_login(message: str):
    flash(message, "warning")
    return redirect(url_for("auth.login", next=request.full_path if request.query_string else request.path))


def safe_redirect_target(target: str | None) -> str | None:
    if not target:
        return None
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    if test_url.scheme in {"http", "https"} and ref_url.netloc == test_url.netloc:
        return target
    return None


def login_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not getattr(g, "current_user", None):
            return _redirect_to_login("请先登录")
        return view(*args, **kwargs)

    return wrapped


def admin_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if not user:
            return _redirect_to_login("请先登录")
        if not user.is_admin:
            flash("需要店长权限", "warning")
            return redirect(url_for("public.index"))
        return view(*args, **kwargs)

    return wrapped


def staff_or_admin_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if not user:
            return _redirect_to_login("请先登录")
        if not user.is_admin and not user.is_staff:
            flash("需要店员或店长权限", "warning")
            return redirect(url_for("public.index"))
        return view(*args, **kwargs)

    return wrapped
