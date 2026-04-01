import logging

from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db
from .models import Letter, ReplyRequest, User


logger = logging.getLogger(__name__)


def bootstrap_database() -> None:
    db.create_all()
    _upgrade_legacy_schema()
    _ensure_indexes()
    _encrypt_legacy_phone_data()
    db.session.commit()
    _ensure_bootstrap_admin()


def _upgrade_legacy_schema() -> None:
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())

    if "users" in tables:
        user_columns = {column["name"] for column in inspector.get_columns("users")}
        if "is_staff" not in user_columns:
            db.session.execute(text("ALTER TABLE users ADD COLUMN is_staff BOOLEAN DEFAULT FALSE"))

    if "letters" in tables:
        letter_columns = {column["name"] for column in inspector.get_columns("letters")}
        if "type" not in letter_columns:
            db.session.execute(text("ALTER TABLE letters ADD COLUMN type VARCHAR(16) DEFAULT 'letter'"))
        if "phone_number" not in letter_columns:
            db.session.execute(text("ALTER TABLE letters ADD COLUMN phone_number TEXT"))
        if "preferred_call_time" not in letter_columns:
            db.session.execute(text("ALTER TABLE letters ADD COLUMN preferred_call_time TEXT"))


def _ensure_indexes() -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS ix_letters_user_id ON letters (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_letters_type ON letters (type)",
        "CREATE INDEX IF NOT EXISTS ix_letters_created_at ON letters (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_replies_letter_id ON replies (letter_id)",
        "CREATE INDEX IF NOT EXISTS ix_replies_admin_id ON replies (admin_id)",
        "CREATE INDEX IF NOT EXISTS ix_reply_requests_status ON reply_requests (status)",
        "CREATE INDEX IF NOT EXISTS ix_reply_requests_staff_letter ON reply_requests (staff_id, letter_id)",
    ]
    for statement in statements:
        db.session.execute(text(statement))


def _encrypt_legacy_phone_data() -> None:
    letters = (
        Letter.query.filter(Letter.type == "phone")
        .filter(Letter.phone_number_raw.isnot(None))
        .all()
    )

    changed = 0
    for letter in letters:
        if not letter.phone_number_raw:
            continue
        if not letter.phone_number_is_encrypted:
            plain_phone = letter.phone_number_raw.strip()
            if plain_phone:
                letter.phone_number = plain_phone
                changed += 1

        if letter.preferred_call_time_raw and not letter.preferred_call_time_is_encrypted:
            plain_time = letter.preferred_call_time_raw.strip()
            if plain_time:
                letter.preferred_call_time = plain_time
                changed += 1

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
        changed = False
        if not existing.is_admin or existing.is_staff:
            existing.is_admin = True
            existing.is_staff = False
            changed = True
            logger.info("Promoted existing account %s to admin.", username)
        if not check_password_hash(existing.password_hash, password):
            existing.password_hash = generate_password_hash(password)
            changed = True
            logger.info("Updated bootstrap admin password for %s from environment.", username)
        if changed:
            db.session.commit()
        return

    admin = User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=True,
        is_staff=False,
    )
    db.session.add(admin)
    try:
        db.session.commit()
        logger.info("Created bootstrap admin %s.", username)
    except IntegrityError:
        db.session.rollback()
