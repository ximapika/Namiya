"""Session-bound, single-use email proofs; no address is persisted."""
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app, session
from sqlalchemy import case, or_, update

from ..extensions import db
from ..models_verification import EmailDeliveryLimit, EmailVerification
from .mail import MailUnavailable, send_verification_code


EMAIL_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}@[a-z0-9.-]+$", re.ASCII)


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class VerificationError(ValueError):
    pass


class EmailRateLimited(VerificationError):
    pass


def normalize_email(value: str) -> str:
    value = value.strip().lower()
    allowed = current_app.config["ALLOWED_EMAIL_DOMAINS"]
    if (len(value) > 254 or not EMAIL_PATTERN.fullmatch(value)
            or value.rsplit("@", 1)[-1] not in allowed):
        raise VerificationError("请使用 @pku.edu.cn 或 @stu.pku.edu.cn 邮箱。")
    local = value.split("@", 1)[0]
    if ".." in local or local.endswith("."):
        raise VerificationError("邮箱格式不正确。")
    return value


def email_digest(email: str) -> str:
    key = current_app.config["EMAIL_LOOKUP_KEY"].encode("utf-8")
    return hmac.new(key, b"email-index-v1\0" + email.encode("utf-8"), hashlib.sha256).hexdigest()


def _digest(label: str, value: str) -> str:
    secret = current_app.config["SECRET_KEY"]
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, (label + "\0" + value).encode(), hashlib.sha256).hexdigest()


def _session_hash() -> str:
    if not session.get("email_verification_session"):
        session["email_verification_session"] = secrets.token_urlsafe(32)
    return _digest("email-session", session["email_verification_session"])


def _reserve_delivery(digest: str, now: datetime) -> None:
    """One shared database counter covers all purposes, accounts and workers."""
    dialect = db.engine.dialect.name
    if dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    elif dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        raise RuntimeError("Email verification requires SQLite or PostgreSQL.")
    hour = now.replace(minute=0, second=0, microsecond=0)
    db.session.execute(insert(EmailDeliveryLimit).values(
        email_hash=digest, hour_start=hour, sent_count=0,
        last_sent=now - timedelta(days=1),
    ).on_conflict_do_nothing(index_elements=["email_hash"]))
    fresh_hour = EmailDeliveryLimit.hour_start < hour
    result = db.session.execute(update(EmailDeliveryLimit).where(
        EmailDeliveryLimit.email_hash == digest,
        EmailDeliveryLimit.last_sent <= now - timedelta(seconds=current_app.config["EMAIL_RESEND_SECONDS"]),
        or_(fresh_hour, EmailDeliveryLimit.sent_count < current_app.config["EMAIL_HOURLY_LIMIT"]),
    ).values(
        hour_start=hour, last_sent=now,
        sent_count=case((fresh_hour, 1), else_=EmailDeliveryLimit.sent_count + 1),
    ).execution_options(synchronize_session=False))
    if result.rowcount != 1:
        db.session.rollback()
        raise EmailRateLimited("发送过于频繁，请稍后再试。")
    db.session.commit()


def issue_email_verification(email: str, purpose: str, target_auth_id: str | None = None) -> str:
    if purpose not in {"register", "reset", "bind_email"}:
        raise VerificationError("验证用途无效。")
    email = normalize_email(email)
    now = utcnow()
    digest = email_digest(email)
    _reserve_delivery(digest, now)
    challenge_id = secrets.token_hex(16)
    code = f"{secrets.randbelow(1_000_000):06d}"
    record = EmailVerification(
        id=challenge_id, purpose=purpose, email_hash=digest,
        code_hash=_digest("email-code", challenge_id + ":" + code),
        session_hash=_session_hash(), target_auth_id=target_auth_id,
        expires_at=now + timedelta(seconds=current_app.config["EMAIL_CODE_TTL_SECONDS"]),
    )
    db.session.add(record)
    db.session.commit()
    try:
        send_verification_code(email, code)
    except MailUnavailable:
        record.consumed_at = utcnow()
        db.session.commit()
        raise
    return challenge_id


def consume_email_verification(challenge_id: str, code: str, email: str, purpose: str,
                               target_auth_id: str | None = None) -> None:
    """Consume in caller's transaction; wrong guesses commit their attempt count."""
    error = "邮箱验证码无效或已过期，请重新获取。"
    if not re.fullmatch(r"[a-f0-9]{32}", challenge_id or ""):
        raise VerificationError(error)
    digest = email_digest(normalize_email(email))
    now = utcnow()
    conditions = (
        EmailVerification.id == challenge_id,
        EmailVerification.purpose == purpose,
        EmailVerification.email_hash == digest,
        EmailVerification.session_hash == _session_hash(),
        EmailVerification.target_auth_id == target_auth_id,
        EmailVerification.consumed_at.is_(None),
        EmailVerification.expires_at > now,
        EmailVerification.attempts < current_app.config["EMAIL_CODE_MAX_ATTEMPTS"],
    )
    result = db.session.execute(update(EmailVerification).where(*conditions).values(
        attempts=EmailVerification.attempts + 1,
    ).execution_options(synchronize_session=False))
    if result.rowcount != 1:
        db.session.rollback()
        raise VerificationError(error)
    record = db.session.get(EmailVerification, challenge_id, populate_existing=True)
    expected = _digest("email-code", challenge_id + ":" + code.strip())
    if not hmac.compare_digest(record.code_hash, expected):
        db.session.commit()
        raise VerificationError(error)
    record.consumed_at = now
    db.session.flush()
