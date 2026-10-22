"""RSA-OAEP transport envelopes; HTTPS is still required against active MITM.

The browser encrypts a password for one short-lived browser/purpose challenge.
Passwords are separately stored with a one-way scrypt hash by the auth service.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import stat
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import current_app, request

from ..extensions import db
from ..models_challenges import PasswordChallenge
from .captcha import browser_hash, utcnow


PURPOSES = frozenset({"login", "register", "reset", "change", "bind_email"})


class PasswordTransportError(ValueError):
    pass


def _new_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def init_password_transport(app):
    path_value = app.config.get("PASSWORD_TRANSPORT_PRIVATE_KEY_FILE")
    production = app.config.get("REQUIRE_RUNTIME_SECRETS", False)
    if production and not path_value:
        raise RuntimeError("PASSWORD_TRANSPORT_PRIVATE_KEY_FILE is required in production.")
    if app.testing and not path_value:
        key = _new_private_key()
    else:
        path = Path(path_value) if path_value else Path(app.instance_path) / "password-transport.pem"
        if not path.exists() and not production:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Publish a fully written file atomically; concurrent dev workers
            # all load the winner, never a truncated or per-worker private key.
            temporary = path.with_name(path.name + "." + secrets.token_hex(12) + ".tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(_private_pem(_new_private_key()))
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    pass
            finally:
                temporary.unlink(missing_ok=True)
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("Password transport private key must be a regular file.")
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise RuntimeError("Password transport private key must have owner-only permissions (0600).")
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise RuntimeError("Password transport requires an RSA private key of at least 3072 bits.")
    if key.public_key().public_numbers().e != 65537:
        raise RuntimeError("Password transport requires RSA exponent 65537.")
    app.extensions["password_transport_key"] = key


def create_password_challenge(purpose):
    if purpose not in PURPOSES:
        raise PasswordTransportError("无效的密码提交用途")
    now = utcnow()
    expired = db.select(PasswordChallenge.id).where(PasswordChallenge.expires_at <= now).limit(100)
    db.session.execute(db.delete(PasswordChallenge).where(PasswordChallenge.id.in_(expired)))
    nonce = secrets.token_urlsafe(32)
    challenge_id = secrets.token_urlsafe(32)
    row = PasswordChallenge(
        id=challenge_id, browser_hash=browser_hash(create=True),
        nonce_digest=hashlib.sha256(nonce.encode("ascii")).hexdigest(), purpose=purpose,
        expires_at=now + timedelta(seconds=current_app.config.get("PASSWORD_CHALLENGE_TTL_SECONDS", 300)),
    )
    db.session.add(row)
    db.session.commit()
    key = current_app.extensions["password_transport_key"]
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return {"id": challenge_id, "nonce": nonce, "public_key": public_key,
            "algorithm": "RSA-OAEP-SHA256", "max_password_bytes": 128}


def decrypt_password_submission(purpose):
    """Return (password, confirm) for one envelope, never accept plaintext.

    The UI compares confirmation locally; only one password is encrypted.
    Consuming the nonce is committed before decryption/business changes.
    """
    error = PasswordTransportError("密码加密验证失败，请刷新页面后重试")
    if purpose not in PURPOSES or "password" in request.form or "confirm" in request.form:
        raise error
    challenge_id = request.form.get("password_challenge", "")
    envelope = request.form.get("password_envelope", "")
    if len(challenge_id) != 43 or not browser_hash() or not envelope or len(envelope) > 1400:
        raise error
    row = db.session.execute(db.select(PasswordChallenge).where(
        PasswordChallenge.id == challenge_id,
        PasswordChallenge.browser_hash == browser_hash(),
        PasswordChallenge.purpose == purpose,
        PasswordChallenge.expires_at > utcnow(),
    )).scalar_one_or_none()
    if row is None:
        raise error
    nonce_digest = row.nonce_digest
    deleted = db.session.execute(db.delete(PasswordChallenge).where(
        PasswordChallenge.id == challenge_id,
        PasswordChallenge.browser_hash == browser_hash(),
        PasswordChallenge.purpose == purpose,
        PasswordChallenge.expires_at > utcnow(),
    ), execution_options={"synchronize_session": False}).rowcount
    db.session.commit()
    if deleted != 1:
        raise error
    try:
        encrypted = base64.b64decode(envelope, validate=True)
        key = current_app.extensions["password_transport_key"]
        if len(encrypted) != (key.key_size + 7) // 8:
            raise error
        decoded = key.decrypt(encrypted, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None,
        ))
        payload = json.loads(decoded.decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {"nonce", "password_b64"}:
            raise error
        nonce, password_b64 = payload["nonce"], payload["password_b64"]
        if not isinstance(nonce, str) or len(nonce) != 43 or not isinstance(password_b64, str):
            raise error
        if not hmac.compare_digest(nonce_digest, hashlib.sha256(nonce.encode("ascii")).hexdigest()):
            raise error
        password_bytes = base64.b64decode(password_b64, validate=True)
        if not 1 <= len(password_bytes) <= 128:
            raise error
        password = password_bytes.decode("utf-8")
    except (ValueError, TypeError, KeyError, binascii.Error, UnicodeError):
        raise error from None
    return password, password
