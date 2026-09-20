import base64
import hashlib

from cryptography.fernet import Fernet
from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect


db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


class PhoneCipher:
    def init_app(self, app) -> None:
        key = self._normalize_key(app.config["PHONE_ENCRYPTION_KEY"])
        app.extensions["phone_cipher"] = Fernet(key.encode("utf-8"))

    @property
    def _fernet(self):
        return current_app.extensions["phone_cipher"]

    def encrypt(self, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return "enc:v1:" + self._fernet.encrypt(value.strip().encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str | None) -> str:
        if not value:
            return ""
        if not self.is_encrypted(value):
            return value
        token = value.removeprefix("enc:v1:")
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")

    def is_encrypted(self, value: str | None) -> bool:
        if not value:
            return False
        # Recognize legacy Fernet values independently of the configured key.
        # Authenticate them before allowing any migration to proceed.
        encrypted = value.startswith(("enc:", "gAAAA"))
        if not encrypted:
            try:
                raw = base64.urlsafe_b64decode(value.encode("ascii"))
                encrypted = len(raw) >= 73 and raw[0] == 0x80
            except (ValueError, UnicodeError):
                pass
        if encrypted:
            token = value.removeprefix("enc:v1:")
            self._fernet.decrypt(token.encode("utf-8"))
        return encrypted

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
