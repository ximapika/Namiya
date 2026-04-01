import os
from pathlib import Path

from flask import Flask, g, request, session
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from .auth import sync_session_from_user
from .cli import register_cli
from .content import THEME_OPTIONS, active_theme_name
from .extensions import csrf, db, limiter, phone_cipher
from .models import User
from .routes.admin import admin_bp
from .routes.auth import auth_bp
from .routes.public import public_bp
from .routes.user import user_bp
from .services.runtime import ensure_runtime_secrets


def create_app(config_name: str | None = None, test_config: dict | None = None) -> Flask:
    project_root = Path(__file__).resolve().parent.parent
    load_dotenv(project_root / ".env")
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

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    phone_cipher.init_app(app)
    register_cli(app)

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    @app.before_request
    def load_current_user() -> None:
        g.current_user = None
        user_id = session.get("user_id")
        if not user_id:
            return

        user = db.session.get(User, user_id)
        if not user:
            theme_name = session.get("theme_name")
            session.clear()
            if theme_name:
                session["theme_name"] = theme_name
            return

        g.current_user = user
        sync_session_from_user(user, preserve_theme=True)

    @app.context_processor
    def inject_global_context() -> dict:
        return {
            "active_theme": active_theme_name(),
            "theme_options": THEME_OPTIONS,
        }

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
            "script-src 'self' 'unsafe-inline'",
            "font-src 'self' data:",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
        ]
        response.headers.setdefault("Content-Security-Policy", "; ".join(csp))

        if app.config.get("ENABLE_HSTS") and request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    return app
