import base64
import hashlib
import logging
import secrets
from pathlib import Path


logger = logging.getLogger(__name__)


def ensure_runtime_secrets(app) -> None:
    app.config["SECRET_KEY"] = _resolve_material(
        app=app,
        configured_value=app.config.get("SECRET_KEY"),
        filename="secret.key",
        label="SECRET_KEY",
        bytes_length=48,
        transform=lambda raw: raw,
    )
    app.config["PHONE_ENCRYPTION_KEY"] = _resolve_material(
        app=app,
        configured_value=app.config.get("PHONE_ENCRYPTION_KEY"),
        filename="phone_encryption.key",
        label="PHONE_ENCRYPTION_KEY",
        bytes_length=32,
        transform=lambda raw: base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest()).decode("utf-8"),
    )


def _resolve_material(app, configured_value, filename: str, label: str, bytes_length: int, transform):
    if configured_value:
        return configured_value

    require_secrets = app.config.get("REQUIRE_RUNTIME_SECRETS", False)
    target = Path(app.instance_path) / filename
    if target.exists():
        value = target.read_text(encoding="utf-8").strip()
        if value:
            return value

    if require_secrets:
        raise RuntimeError(f"{label} is required in production. Configure it via environment variables.")

    raw = secrets.token_urlsafe(bytes_length)
    value = transform(raw)
    target.write_text(value, encoding="utf-8")
    logger.warning("%s was not configured. Generated a development secret at %s", label, target)
    return value
