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
        "DEBUG": False,
        "TRUST_PROXY": _env_flag("TRUST_PROXY"),
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
        "EMAIL_LOOKUP_KEY": os.getenv("EMAIL_LOOKUP_KEY"),
        "ALLOWED_EMAIL_DOMAINS": ("pku.edu.cn", "stu.pku.edu.cn"),
        "EMAIL_CODE_TTL_SECONDS": int(os.getenv("EMAIL_CODE_TTL_SECONDS", "600")),
        "EMAIL_CODE_MAX_ATTEMPTS": 5,
        "EMAIL_RESEND_SECONDS": int(os.getenv("EMAIL_RESEND_SECONDS", "60")),
        "EMAIL_HOURLY_LIMIT": int(os.getenv("EMAIL_HOURLY_LIMIT", "5")),
        "EMAIL_SEND_RATE_LIMIT": os.getenv("EMAIL_SEND_RATE_LIMIT", "3 per minute"),
        "MAIL_HOST": os.getenv("MAIL_HOST", ""),
        "MAIL_PORT": int(os.getenv("MAIL_PORT", "465")),
        "MAIL_FROM": os.getenv("MAIL_FROM", ""),
        "MAIL_USERNAME": os.getenv("MAIL_USERNAME", ""),
        "MAIL_PASSWORD": os.getenv("MAIL_PASSWORD", ""),
        "MAIL_USE_SSL": _env_flag("MAIL_USE_SSL", True),
        "MAIL_USE_TLS": _env_flag("MAIL_USE_TLS", False),
        "MAIL_TIMEOUT_SECONDS": 10,
        "PASSWORD_TRANSPORT_PRIVATE_KEY_FILE": os.getenv("PASSWORD_TRANSPORT_PRIVATE_KEY_FILE", ""),
        "PASSWORD_CHALLENGE_TTL_SECONDS": 300,
        "CAPTCHA_TTL_SECONDS": 300,
        "CHALLENGE_RATE_LIMIT": os.getenv("CHALLENGE_RATE_LIMIT", "20 per minute"),
        "USER_REQUEST_RATE_LIMIT": os.getenv("USER_REQUEST_RATE_LIMIT", "60 per minute"),
        "IP_REQUEST_RATE_LIMIT": os.getenv("IP_REQUEST_RATE_LIMIT", "120 per minute"),
        "DAILY_MESSAGE_LIMIT": int(os.getenv("DAILY_MESSAGE_LIMIT", "5")),
        "DAILY_MESSAGE_TIMEZONE": os.getenv("DAILY_MESSAGE_TIMEZONE", "Asia/Shanghai"),
        "PAGE_SIZE": int(os.getenv("PAGE_SIZE", "20")),
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
