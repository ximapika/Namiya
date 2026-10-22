from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import current_app
from sqlalchemy import func, literal, select, update
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from ..extensions import db
from ..models import Letter, User
from ..models_usage import DailyUsage


def consume_daily_message(user, *, now: datetime | None = None) -> bool:
    """Reserve one submission in the caller's transaction, never committing it.

    The conditional UPDATE serializes concurrent submissions in the database.
    A failed letter insertion or caller rollback also rolls back this reservation.
    Existing letters are counted when introducing quotas to an existing database.
    """
    limit = int(current_app.config.get("DAILY_MESSAGE_LIMIT", 5))
    if limit <= 0:
        return False
    # Serialize with password resets/deletions as well. Otherwise a request
    # authenticated before a reset could create a fresh row under its old key
    # after reset_password has already transferred the previous allowance.
    account = db.session.execute(
        update(User).where(User.id == user.id, User.auth_id == user.auth_id)
        .values(auth_id=User.auth_id).execution_options(synchronize_session=False)
    )
    if account.rowcount != 1:
        return False
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    local_tz = ZoneInfo(current_app.config.get("DAILY_MESSAGE_TIMEZONE", "Asia/Shanghai"))
    day = now.astimezone(local_tz).date()
    start = datetime.combine(day, time.min, tzinfo=local_tz)
    end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=local_tz)
    start_utc = start.astimezone(timezone.utc).replace(tzinfo=None)
    end_utc = end.astimezone(timezone.utc).replace(tzinfo=None)

    dialect = db.session.get_bind().dialect.name
    insert = {"sqlite": sqlite_insert, "postgresql": postgres_insert}.get(dialect)
    if insert is None:
        raise RuntimeError("Daily quotas require SQLite or PostgreSQL.")
    initial_count = select(
        literal(user.auth_id), literal(day), func.count(Letter.id)
    ).where(
        Letter.user_id == user.id,
        Letter.created_at >= start_utc,
        Letter.created_at < end_utc,
    )
    statement = insert(DailyUsage).from_select(
        ["auth_id", "day", "message_count"], initial_count
    ).on_conflict_do_nothing(index_elements=["auth_id", "day"])
    db.session.execute(statement)
    reserved = db.session.execute(
        update(DailyUsage)
        .where(DailyUsage.auth_id == user.auth_id, DailyUsage.day == day,
               DailyUsage.message_count < limit)
        .values(message_count=DailyUsage.message_count + 1)
        .execution_options(synchronize_session=False)
    )
    return reserved.rowcount == 1
