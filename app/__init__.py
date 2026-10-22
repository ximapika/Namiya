import os
import hmac
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Flask, current_app, g, request, session
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy.orm.exc import ObjectDeletedError

from .auth import sync_session_from_user
from .cli import register_cli
from .content import THEME_OPTIONS, active_theme_name
from .extensions import csrf, db, limiter, phone_cipher
from .models import User
from . import models_verification, models_usage, models_challenges
from .routes.admin import admin_bp
from .routes.auth import auth_bp
from .routes.public import public_bp
from .routes.user import user_bp
from .routes.challenges import challenges_bp
from .services.accounts import record_activity
from .services.password_transport import init_password_transport
from .services.rate_limits import user_rate_key
from .services.runtime import ensure_runtime_secrets


@limiter.shared_limit(
    lambda: current_app.config["IP_REQUEST_RATE_LIMIT"], scope="all-dynamic-ip",
    key_func=lambda: request.remote_addr or "unknown",
)
@limiter.shared_limit(
    lambda: current_app.config["USER_REQUEST_RATE_LIMIT"], scope="all-dynamic-account",
    key_func=user_rate_key, exempt_when=lambda: not getattr(g, "current_user", None),
)
def enforce_dynamic_request_limits():
    """Run shared account/IP limits independently of endpoint overrides."""
    return None


def create_app(config_name: str | None = None, test_config: dict | None = None) -> Flask:
    project_root = Path(__file__).resolve().parent.parent
    load_dotenv(project_root / ".env")
    if "." in __package__:
        from ..config import build_app_config
    else:
        from config import build_app_config

    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
    )

    selected = config_name or os.getenv("APP_ENV") or os.getenv("FLASK_ENV") or "development"
    app.config.from_mapping(build_app_config(selected))

    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    ensure_runtime_secrets(app)
    init_password_transport(app)
    app.extensions["dummy_password_hash"] = generate_password_hash(os.urandom(32).hex(), method="scrypt")

    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)

    db.init_app(app)
    phone_cipher.init_app(app)
    register_cli(app)

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(challenges_bp)

    @app.before_request
    def load_current_user() -> None:
        g.current_user = None
        user_id = session.get("user_id")
        if not user_id:
            return

        user = db.session.get(User, user_id)
        identity = session.get("auth_id", "")
        if not user or not isinstance(identity, str) or not hmac.compare_digest(user.auth_id, identity):
            theme_name = session.get("theme_name")
            session.clear()
            if theme_name:
                session["theme_name"] = theme_name
            return

        try:
            valid = record_activity(user) and hmac.compare_digest(user.auth_id, identity)
        except ObjectDeletedError:
            valid = False
        if not valid:
            session.clear()
            return
        g.current_user = user
        sync_session_from_user(user, preserve_theme=True, verified_auth_id=identity)

    # A separate hook keeps global budgets effective even on routes whose
    # endpoint-specific decorator overrides inherited/default limits. Register
    # after identity loading and before Limiter's normal endpoint evaluation.
    app.before_request(enforce_dynamic_request_limits)
    limiter.init_app(app)
    csrf.init_app(app)

    @app.context_processor
    def inject_global_context() -> dict:
        return {
            "active_theme": active_theme_name(),
            "theme_options": THEME_OPTIONS,
        }

    @app.template_filter("localtime")
    def localtime_filter(value, fmt="%Y-%m-%d %H:%M"):
        """Render a naive UTC datetime in the configured display timezone."""
        if value is None:
            return ""
        if isinstance(value, datetime):
            dt = value
        else:
            return str(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=dt_timezone.utc)
        tz_name = app.config.get("DISPLAY_TIMEZONE", "Asia/Shanghai")
        try:
            local = dt.astimezone(ZoneInfo(tz_name))
        except Exception:
            local = dt
        return local.strftime(fmt)

    @app.after_request
    def apply_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        csp = [
            "default-src 'self'",
            "img-src 'self' data:",
            "style-src 'self' 'unsafe-inline'",
            "script-src 'self'",
            "font-src 'self' data:",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ]
        response.headers.setdefault("Content-Security-Policy", "; ".join(csp))

        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"

        if app.config.get("ENABLE_HSTS") and request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    return app
