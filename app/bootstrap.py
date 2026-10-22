import logging
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from .extensions import db
from .models import Letter, User


logger = logging.getLogger(__name__)


def bootstrap_database() -> None:
    db.create_all()
    _upgrade_legacy_schema()
    _ensure_indexes()
    _encrypt_legacy_phone_data()
    db.session.commit()
    _ensure_bootstrap_admin()


def _upgrade_legacy_schema() -> None:
    # Reuse the migration connection: a second inspector connection can roll
    # back in-memory SQLite's shared connection while a migration is in flight.
    inspector = inspect(db.session.connection())
    tables = set(inspector.get_table_names())

    if "users" in tables:
        user_columns = {column["name"] for column in inspector.get_columns("users")}
        if "is_staff" not in user_columns:
            db.session.execute(text("ALTER TABLE users ADD COLUMN is_staff BOOLEAN DEFAULT FALSE"))
        additions = {
            "auth_id": "VARCHAR(32)",
            "last_active_at": "TIMESTAMP",
            "email_hash": "VARCHAR(64)",
            "email_slot": "INTEGER",
        }
        for name, definition in additions.items():
            if name not in user_columns:
                db.session.execute(text(f"ALTER TABLE users ADD COLUMN {name} {definition}"))

        # Existing accounts receive a complete grace period from migration,
        # rather than being deleted based on an old creation timestamp.
        db.session.execute(text(
            "UPDATE users SET last_active_at = :now WHERE last_active_at IS NULL"
        ), {"now": datetime.now(timezone.utc).replace(tzinfo=None)})
        while True:
            legacy_ids = db.session.execute(text(
                "SELECT id FROM users WHERE auth_id IS NULL OR auth_id = '' LIMIT 500"
            )).scalars().all()
            if not legacy_ids:
                break
            for user_id in legacy_ids:
                db.session.execute(text("UPDATE users SET auth_id = :token WHERE id = :id"),
                                   {"token": uuid4().hex, "id": user_id})
        _enforce_user_constraints()

    if "letters" in tables:
        letter_columns = {column["name"] for column in inspector.get_columns("letters")}
        if "type" not in letter_columns:
            db.session.execute(text("ALTER TABLE letters ADD COLUMN type VARCHAR(16) DEFAULT 'letter'"))
        if "phone_number" not in letter_columns:
            db.session.execute(text("ALTER TABLE letters ADD COLUMN phone_number TEXT"))
        if "preferred_call_time" not in letter_columns:
            db.session.execute(text("ALTER TABLE letters ADD COLUMN preferred_call_time TEXT"))


def _enforce_user_constraints() -> None:
    """Upgrade old tables without a destructive SQLite users-table rebuild."""
    db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_auth_id ON users (auth_id)"))
    db.session.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_slot ON users (email_hash, email_slot)"
    ))
    if db.engine.dialect.name == "sqlite":
        # ALTER TABLE cannot add CHECK/NOT NULL constraints to legacy SQLite
        # columns. These triggers enforce the same invariant for every writer.
        for action in ("INSERT", "UPDATE"):
            db.session.execute(text(f"""
                CREATE TRIGGER IF NOT EXISTS users_identity_{action.lower()}
                BEFORE {action} ON users
                WHEN NEW.auth_id IS NULL OR NEW.auth_id = '' OR NEW.last_active_at IS NULL
                BEGIN SELECT RAISE(ABORT, 'users identity and activity are required'); END
            """))
            db.session.execute(text(f"""
                CREATE TRIGGER IF NOT EXISTS users_email_slot_{action.lower()}
                BEFORE {action} ON users
                WHEN NOT (
                    (NEW.email_hash IS NULL AND NEW.email_slot IS NULL) OR
                    (NEW.email_hash IS NOT NULL AND NEW.email_slot IS NOT NULL
                     AND NEW.email_slot BETWEEN 1 AND 3)
                )
                BEGIN SELECT RAISE(ABORT, 'invalid verified email slot'); END
            """))
    elif db.engine.dialect.name == "postgresql":
        db.session.execute(text("ALTER TABLE users ALTER COLUMN auth_id SET NOT NULL"))
        db.session.execute(text("ALTER TABLE users ALTER COLUMN last_active_at SET NOT NULL"))
        constraints = {c["name"] for c in inspect(db.session.connection()).get_check_constraints("users")}
        if "ck_users_email_slot" not in constraints:
            db.session.execute(text("""
                ALTER TABLE users ADD CONSTRAINT ck_users_email_slot CHECK (
                    (email_hash IS NULL AND email_slot IS NULL) OR
                    (email_hash IS NOT NULL AND email_slot IS NOT NULL
                     AND email_slot BETWEEN 1 AND 3)
                )
            """))


def _ensure_indexes() -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS ix_letters_user_id ON letters (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_letters_type ON letters (type)",
        "CREATE INDEX IF NOT EXISTS ix_letters_created_at ON letters (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_replies_letter_id ON replies (letter_id)",
        "CREATE INDEX IF NOT EXISTS ix_replies_admin_id ON replies (admin_id)",
        "CREATE INDEX IF NOT EXISTS ix_reply_requests_status ON reply_requests (status)",
        "CREATE INDEX IF NOT EXISTS ix_reply_requests_staff_letter ON reply_requests (staff_id, letter_id)",
        "CREATE INDEX IF NOT EXISTS ix_users_last_active_at ON users (last_active_at)",
        "CREATE INDEX IF NOT EXISTS ix_users_email_hash ON users (email_hash)",
        "CREATE INDEX IF NOT EXISTS ix_users_roles_created ON users (is_admin, is_staff, created_at, id)",
        "CREATE INDEX IF NOT EXISTS ix_users_roles_activity ON users (is_admin, is_staff, last_active_at, id)",
        "CREATE INDEX IF NOT EXISTS ix_letters_user_created ON letters (user_id, created_at, id)",
        "CREATE INDEX IF NOT EXISTS ix_letters_type_created ON letters (type, created_at, id)",
        "CREATE INDEX IF NOT EXISTS ix_replies_letter_created ON replies (letter_id, created_at, id)",
        "CREATE INDEX IF NOT EXISTS ix_reply_requests_status_created ON reply_requests (status, created_at, id)",
    ]
    for statement in statements:
        db.session.execute(text(statement))


def _encrypt_legacy_phone_data() -> None:
    from .extensions import phone_cipher

    # Preflight all ciphertext before changing any data, including fields on
    # old records whose type/phone number was absent. Use bounded keyset scans
    # so startup does not materialize every letter and its content in memory.
    def batches():
        last_id = 0
        while True:
            rows = db.session.execute(select(
                Letter.id, Letter.phone_number_raw, Letter.preferred_call_time_raw
            ).where(Letter.id > last_id).order_by(Letter.id).limit(500)).all()
            if not rows:
                return
            yield rows
            last_id = rows[-1].id

    for rows in batches():
        for _, phone, preferred_time in rows:
            for value in (phone, preferred_time):
                if value:
                    phone_cipher.is_encrypted(value)
    changed = 0
    for rows in batches():
        for letter_id, phone, preferred_time in rows:
            values = {}
            for column, value in (("phone_number_raw", phone),
                                  ("preferred_call_time_raw", preferred_time)):
                if value and not phone_cipher.is_encrypted(value):
                    values[column] = phone_cipher.encrypt(value)
            if values:
                db.session.execute(update(Letter).where(Letter.id == letter_id).values(**values)
                                   .execution_options(synchronize_session=False))
                changed += len(values)
    if changed:
        logger.info("Encrypted %s legacy phone/contact fields.", changed)


def _ensure_bootstrap_admin() -> None:
    from flask import current_app

    username = current_app.config.get("BOOTSTRAP_ADMIN_USERNAME", "").strip()
    password = current_app.config.get("BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not password:
        return

    existing = User.query.filter_by(username=username).first()
    if existing:
        logger.info("Bootstrap account already exists; leaving credentials and roles unchanged.")
        return

    admin = User(
        username=username,
        password_hash=generate_password_hash(password, method="scrypt"),
        is_admin=True,
        is_staff=False,
    )
    db.session.add(admin)
    try:
        db.session.commit()
        logger.info("Created bootstrap admin %s.", username)
    except IntegrityError:
        db.session.rollback()
