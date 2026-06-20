import os
from datetime import timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"


def _env_flag(name: str, default: bool = False) -> bool:
    fallback = "true" if default else "false"
    return os.getenv(name, fallback).strip().lower() == "true"


def normalize_database_uri(uri: str) -> str:
    normalized = uri.strip()
    if not normalized:
        return f"sqlite:///{(INSTANCE_DIR / 'worryshop.db').resolve()}"

    if normalized.startswith("postgres://"):
        normalized = normalized.replace("postgres://", "postgresql://", 1)

    if not normalized.startswith("sqlite:"):
        return normalized

    if normalized == "sqlite:///:memory:":
        return normalized

    prefix = "sqlite:///"
    if not normalized.startswith(prefix):
        return normalized

    raw_path = Path(normalized[len(prefix):]).expanduser()
    if not raw_path.is_absolute():
        raw_path = (BASE_DIR / raw_path).resolve()

    return f"sqlite:///{raw_path}"


def default_database_uri() -> str:
    return normalize_database_uri(f"sqlite:///{INSTANCE_DIR / 'worryshop.db'}")


def resolve_database_uri(config_name: str) -> str:
    selected = (config_name or "development").lower()
    testing = selected in {"testing", "test"}
    production = selected in {"production", "prod"}

    if testing:
        return "sqlite:///:memory:"

    configured = os.getenv("DATABASE_URL", "").strip()
    if configured:
        return normalize_database_uri(configured)

    if production:
        raise RuntimeError("DATABASE_URL is required in production.")

    return default_database_uri()


def _sqlalchemy_engine_options(database_uri: str) -> dict:
    options = {
        "pool_pre_ping": True,
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "1800")),
    }

    if database_uri.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        return options

    options["pool_size"] = int(os.getenv("DB_POOL_SIZE", "10"))
    options["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "20"))
    return options


def build_app_config(config_name: str) -> dict:
    selected = (config_name or "development").lower()
    testing = selected in {"testing", "test"}
    production = selected in {"production", "prod"}

    database_uri = resolve_database_uri(selected)

    return {
        "DEBUG": not testing and not production,
        "TESTING": testing,
        "SECRET_KEY": os.getenv("SECRET_KEY"),
        "SQLALCHEMY_DATABASE_URI": database_uri,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_ENGINE_OPTIONS": _sqlalchemy_engine_options(database_uri),
        "SESSION_COOKIE_NAME": os.getenv("SESSION_COOKIE_NAME", "worryshop_session"),
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
        "SESSION_COOKIE_SECURE": _env_flag("SESSION_COOKIE_SECURE"),
        "SESSION_REFRESH_EACH_REQUEST": True,
        "PERMANENT_SESSION_LIFETIME": timedelta(
            hours=int(os.getenv("SESSION_LIFETIME_HOURS", "12"))
        ),
        "MAX_CONTENT_LENGTH": int(os.getenv("MAX_CONTENT_LENGTH", str(256 * 1024))),
        "WTF_CSRF_TIME_LIMIT": int(os.getenv("WTF_CSRF_TIME_LIMIT", str(2 * 60 * 60))),
        "WTF_CSRF_ENABLED": not testing,
        "RATELIMIT_HEADERS_ENABLED": True,
        "RATELIMIT_STORAGE_URI": os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
        "RATELIMIT_ENABLED": not testing,
        "PHONE_ENCRYPTION_KEY": os.getenv("PHONE_ENCRYPTION_KEY"),
        "PASSWORD_MIN_LENGTH": int(os.getenv("PASSWORD_MIN_LENGTH", "8")),
        "LOGIN_RATE_LIMIT": os.getenv("LOGIN_RATE_LIMIT", "10 per minute"),
        "REGISTER_RATE_LIMIT": os.getenv("REGISTER_RATE_LIMIT", "5 per minute"),
        "WRITE_RATE_LIMIT": os.getenv("WRITE_RATE_LIMIT", "10 per minute"),
        "ADMIN_MUTATION_RATE_LIMIT": os.getenv("ADMIN_MUTATION_RATE_LIMIT", "30 per minute"),
        "BOOTSTRAP_ADMIN_USERNAME": os.getenv("BOOTSTRAP_ADMIN_USERNAME", "").strip(),
        "BOOTSTRAP_ADMIN_PASSWORD": os.getenv("BOOTSTRAP_ADMIN_PASSWORD", ""),
        "PREFERRED_URL_SCHEME": os.getenv("PREFERRED_URL_SCHEME", "https"),
        "ENABLE_HSTS": _env_flag("ENABLE_HSTS"),
        "REQUIRE_RUNTIME_SECRETS": production or _env_flag("REQUIRE_RUNTIME_SECRETS"),
        "DISPLAY_TIMEZONE": os.getenv("DISPLAY_TIMEZONE", "Asia/Shanghai"),
    }
