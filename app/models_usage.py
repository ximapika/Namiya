from .extensions import db


class DailyUsage(db.Model):
    """A quota belongs to an immutable account identity and a local date."""

    __tablename__ = "daily_usage"

    auth_id = db.Column(db.String(32), primary_key=True)
    day = db.Column(db.Date, primary_key=True)
    message_count = db.Column(db.Integer, nullable=False, default=0)
