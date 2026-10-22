from datetime import datetime, timezone

from .extensions import db


class EmailVerification(db.Model):
    __tablename__ = "email_verifications"

    id = db.Column(db.String(32), primary_key=True)
    purpose = db.Column(db.String(16), nullable=False)
    email_hash = db.Column(db.String(64), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False)
    session_hash = db.Column(db.String(64), nullable=False)
    target_auth_id = db.Column(db.String(32), nullable=True, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    consumed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class EmailDeliveryLimit(db.Model):
    __tablename__ = "email_delivery_limits"

    email_hash = db.Column(db.String(64), primary_key=True)
    hour_start = db.Column(db.DateTime, nullable=False, index=True)
    sent_count = db.Column(db.Integer, nullable=False, default=0)
    last_sent = db.Column(db.DateTime, nullable=False)
