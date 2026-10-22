from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, UniqueConstraint

from .extensions import db, phone_cipher


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email_hash", "email_slot", name="uq_users_email_slot"),
        CheckConstraint(
            "(email_hash IS NULL AND email_slot IS NULL) OR "
            "(email_hash IS NOT NULL AND email_slot IS NOT NULL "
            "AND email_slot BETWEEN 1 AND 3)",
            name="ck_users_email_slot",
        ),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True)
    # IDs can be reused by a legacy SQLite table. Sessions bind to this random
    # incarnation token as well, so deletion can never authenticate a new user.
    auth_id = db.Column(db.String(32), nullable=False, unique=True, index=True,
                        default=lambda: uuid4().hex)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, index=True)
    is_staff = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), index=True)
    last_active_at = db.Column(db.DateTime, nullable=False, index=True,
                               default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    # Only a keyed digest is persisted. The slot constraint caps one verified
    # mailbox at three accounts, including simultaneous registration attempts.
    email_hash = db.Column(db.String(64), nullable=True, index=True)
    email_slot = db.Column(db.Integer, nullable=True)

    letters = db.relationship("Letter", back_populates="user", lazy="dynamic")
    replies = db.relationship("Reply", back_populates="admin", lazy="dynamic")
    reply_requests = db.relationship("ReplyRequest", back_populates="staff", lazy="dynamic")


class Letter(db.Model):
    __tablename__ = "letters"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False, default="")
    type = db.Column(db.String(16), nullable=False, default="letter", index=True)
    phone_number_raw = db.Column("phone_number", db.Text, nullable=True)
    preferred_call_time_raw = db.Column("preferred_call_time", db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), index=True)

    user = db.relationship("User", back_populates="letters")
    replies = db.relationship(
        "Reply",
        back_populates="letter",
        cascade="all, delete-orphan",
        order_by="Reply.created_at.asc()",
        lazy="dynamic",
    )
    reply_requests = db.relationship(
        "ReplyRequest",
        back_populates="letter",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @property
    def phone_number(self) -> str:
        return phone_cipher.decrypt(self.phone_number_raw)

    @phone_number.setter
    def phone_number(self, value: str | None) -> None:
        self.phone_number_raw = phone_cipher.encrypt(value)

    @property
    def preferred_call_time(self) -> str:
        return phone_cipher.decrypt(self.preferred_call_time_raw)

    @preferred_call_time.setter
    def preferred_call_time(self, value: str | None) -> None:
        self.preferred_call_time_raw = phone_cipher.encrypt(value)

    @property
    def phone_number_is_encrypted(self) -> bool:
        return phone_cipher.is_encrypted(self.phone_number_raw)

    @property
    def preferred_call_time_is_encrypted(self) -> bool:
        return phone_cipher.is_encrypted(self.preferred_call_time_raw)


class Reply(db.Model):
    __tablename__ = "replies"

    id = db.Column(db.Integer, primary_key=True)
    letter_id = db.Column(db.Integer, db.ForeignKey("letters.id"), nullable=False, index=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), index=True)

    letter = db.relationship("Letter", back_populates="replies")
    admin = db.relationship("User", back_populates="replies")


class ReplyRequest(db.Model):
    __tablename__ = "reply_requests"
    __table_args__ = (
        UniqueConstraint("letter_id", "staff_id", name="uq_reply_requests_letter_staff"),
    )

    id = db.Column(db.Integer, primary_key=True)
    letter_id = db.Column(db.Integer, db.ForeignKey("letters.id"), nullable=False, index=True)
    staff_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), index=True)

    letter = db.relationship("Letter", back_populates="reply_requests")
    staff = db.relationship("User", back_populates="reply_requests")
