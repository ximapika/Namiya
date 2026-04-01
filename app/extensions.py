import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect


db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


class PhoneCipher:
    def __init__(self) -> None:
        self._fernet: Fernet | None = None

    def init_app(self, app) -> None:
        key = self._normalize_key(app.config["PHONE_ENCRYPTION_KEY"])
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._fernet = Fernet(key)

    def encrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        return self._fernet.encrypt(normalized.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str | None) -> str:
        if not value:
            return ""
        if not self.is_encrypted(value):
            return value
        return self._fernet.decrypt(value.encode("utf-8")).decode("utf-8")

    def is_encrypted(self, value: str | None) -> bool:
        if not value:
            return False
        try:
            self._fernet.decrypt(value.encode("utf-8"))
            return True
        except (InvalidToken, ValueError, TypeError):
            return False

    @staticmethod
    def _normalize_key(value: str) -> str:
        try:
            Fernet(value.encode("utf-8"))
            return value
        except Exception:
            return base64.urlsafe_b64encode(
                hashlib.sha256(value.encode("utf-8")).digest()
            ).decode("utf-8")


phone_cipher = PhoneCipher()
