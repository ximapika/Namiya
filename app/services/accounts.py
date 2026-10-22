"""Account incarnation, activity tracking and bounded retention jobs."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm.attributes import set_committed_value
from werkzeug.security import generate_password_hash

from ..extensions import db
from ..models import Letter, Reply, ReplyRequest, User


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class StaleAccountError(ValueError):
    """An account incarnation changed after it was authenticated/selected."""


def reset_password(user: User, password: str) -> None:
    """Set a one-way password hash and revoke every previous login session.

    The caller commits this together with consumption of the recovery proof.
    """
    user_id, old_auth_id = user.id, user.auth_id
    new_password_hash = generate_password_hash(password, method="scrypt")
    new_auth_id = uuid4().hex
    # Proofs authorize a particular incarnation. Waiting for another worker's
    # transaction must not turn an old proof into permission to reset its new
    # password or a replacement account reusing the same legacy numeric ID.
    with db.session.no_autoflush:
        result = db.session.execute(update(User).where(
            User.id == user_id, User.auth_id == old_auth_id,
        ).values(password_hash=new_password_hash, auth_id=new_auth_id)
                                    .execution_options(synchronize_session=False))
    if result.rowcount != 1:
        raise StaleAccountError("账号状态已变更，请重新验证后再试。")
    # Synchronize without scheduling a second ORM UPDATE that lacks the CAS
    # condition. The caller still owns the proof/reset transaction and commit.
    set_committed_value(user, "password_hash", new_password_hash)
    set_committed_value(user, "auth_id", new_auth_id)
    usage_table = db.metadata.tables.get("daily_usage")
    if usage_table is not None and old_auth_id:
        # Password recovery must not provide a fresh daily sending allowance.
        db.session.execute(update(usage_table).where(usage_table.c.auth_id == old_auth_id)
                           .values(auth_id=new_auth_id))


def record_activity(user: User, *, now: datetime | None = None) -> bool:
    """Persist authenticated activity at most once an hour per account.

    The conditional update prevents every simultaneous request from issuing an
    effective write after the first worker refreshes the timestamp.
    """
    current = now or utcnow()
    if user.last_active_at and user.last_active_at > current - timedelta(hours=1):
        return True
    user_id, auth_id = user.id, user.auth_id
    result = db.session.execute(update(User).where(
        User.id == user.id, User.auth_id == user.auth_id,
        User.last_active_at <= current - timedelta(hours=1),
    ).values(last_active_at=current))
    db.session.commit()
    if result.rowcount:
        return True
    # Another worker may have refreshed activity, or cleanup/password reset
    # may have removed the incarnation. Only the former remains authenticated.
    return db.session.execute(select(User.id).where(
        User.id == user_id, User.auth_id == auth_id,
    )).scalar_one_or_none() is not None


def _content_predicates(user_ids: list[int]):
    letter_ids = select(Letter.id).where(Letter.user_id.in_(user_ids))
    return (
        (Reply, "replies", or_(Reply.letter_id.in_(letter_ids), Reply.admin_id.in_(user_ids))),
        (ReplyRequest, "reply_requests", or_(ReplyRequest.letter_id.in_(letter_ids),
                                            ReplyRequest.staff_id.in_(user_ids))),
        (Letter, "letters", Letter.user_id.in_(user_ids)),
    )


def _delete_accounts(user_ids: list[int], auth_ids: list[str]) -> None:
    for model, _, predicate in _content_predicates(user_ids):
        db.session.execute(delete(model).where(predicate)
                           .execution_options(synchronize_session=False))
    for table_name, key in (("daily_usage", "auth_id"),
                            ("email_verifications", "target_auth_id")):
        table = db.metadata.tables.get(table_name)
        if table is not None:
            db.session.execute(delete(table).where(table.c[key].in_(auth_ids)))
    db.session.execute(delete(User).where(User.id.in_(user_ids))
                       .execution_options(synchronize_session=False))


def lock_account_identity(user: User, *, expected_auth_id: str | None = None) -> None:
    """Lock the authenticated incarnation until the caller commits/rolls back."""
    user_id = user.id
    auth_id = user.auth_id if expected_auth_id is None else expected_auth_id
    # Lock and revalidate before touching any related content. The no-op write
    # acquires a row lock on PostgreSQL and a writer lock on SQLite.
    with db.session.no_autoflush:
        result = db.session.execute(update(User).where(
            User.id == user_id, User.auth_id == auth_id,
        ).values(auth_id=User.auth_id).execution_options(synchronize_session=False))
    if result.rowcount != 1:
        raise StaleAccountError("账号状态已变更，请刷新后再试。")


def delete_account(user: User) -> None:
    """Delete an explicitly selected account; caller authorizes and commits."""
    user_id, auth_id = user.id, user.auth_id
    lock_account_identity(user, expected_auth_id=auth_id)
    _delete_accounts([user_id], [auth_id])


def prune_expired_security_records(*, now: datetime | None = None,
                                   batch_size: int = 500) -> dict:
    """Remove a bounded batch per transient table without committing."""
    current = now or utcnow()
    removed = {}
    for name in ("email_verifications", "captcha_challenges", "password_challenges"):
        table = db.metadata.tables.get(name)
        if table is None:
            continue
        expired_ids = select(table.c.id).where(table.c.expires_at < current)
        expired_ids = expired_ids.order_by(table.c.expires_at, table.c.id).limit(batch_size)
        result = db.session.execute(delete(table).where(table.c.id.in_(expired_ids)))
        removed[name] = result.rowcount
    table = db.metadata.tables.get("daily_usage")
    if table is not None:
        from sqlalchemy import tuple_
        expired_keys = select(table.c.auth_id, table.c.day).where(
            table.c.day < (current - timedelta(days=7)).date()
        ).order_by(table.c.day, table.c.auth_id).limit(batch_size)
        result = db.session.execute(delete(table).where(
            tuple_(table.c.auth_id, table.c.day).in_(expired_keys)
        ))
        removed["daily_usage"] = result.rowcount
    table = db.metadata.tables.get("email_delivery_limits")
    if table is not None:
        expired_hashes = select(table.c.email_hash).where(
            table.c.hour_start < current - timedelta(days=1)
        ).order_by(table.c.hour_start, table.c.email_hash).limit(batch_size)
        result = db.session.execute(delete(table).where(table.c.email_hash.in_(expired_hashes)))
        removed["email_delivery_limits"] = result.rowcount
    return removed


def cleanup_inactive_accounts(*, days: int = 90, batch_size: int = 500,
                              apply: bool = False, now: datetime | None = None) -> dict:
    """Inspect/delete one batch, preserving every staff and administrator.

    Applying the job owns a transaction. SQLite acquires its write lock before
    selecting eligible users; PostgreSQL locks those users before deletion.
    This prevents a concurrent login/role grant from slipping between the
    eligibility check and the deletion. Run again to process another batch.
    """
    if days < 90:
        raise ValueError("The account retention period must be at least 90 days.")
    if not 1 <= batch_size <= 5000:
        raise ValueError("batch_size must be between 1 and 5000.")
    cutoff = (now or utcnow()) - timedelta(days=days)
    eligible = select(User.id, User.auth_id).where(
        User.is_admin.is_(False), User.is_staff.is_(False),
        User.last_active_at <= cutoff,
    ).order_by(User.last_active_at, User.id).limit(batch_size)

    try:
        if apply:
            if db.engine.dialect.name == "sqlite":
                # A no-op UPDATE obtains SQLite's RESERVED write lock without
                # changing any row, even when this session already has a read
                # transaction. Do not issue BEGIN inside an existing session.
                db.session.execute(update(User).where(User.id == -1)
                                   .values(last_active_at=User.last_active_at))
            else:
                eligible = eligible.with_for_update()
        accounts = db.session.execute(eligible).all()
        user_ids = [row.id for row in accounts]
        summary = {"applied": apply, "accounts": len(user_ids), "letters": 0,
                   "replies": 0, "reply_requests": 0, "cutoff": cutoff.isoformat(),
                   "batch_size": batch_size}
        if not user_ids:
            if apply:
                summary["expired_records"] = prune_expired_security_records(now=now, batch_size=batch_size)
                db.session.commit()
            return summary
        predicates = _content_predicates(user_ids)
        for model, key, predicate in predicates:
            summary[key] = db.session.query(model).filter(predicate).count()
        if not apply:
            return summary
        _delete_accounts(user_ids, [row.auth_id for row in accounts])
        summary["expired_records"] = prune_expired_security_records(now=now, batch_size=batch_size)
        db.session.commit()
        return summary
    except Exception:
        if apply:
            db.session.rollback()
        raise
