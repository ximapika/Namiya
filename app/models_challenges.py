"""Short-lived, browser-bound challenges shared by every application worker."""

from .extensions import db


class CaptchaChallenge(db.Model):
    __tablename__ = "captcha_challenges"

    id = db.Column(db.String(43), primary_key=True)
    browser_hash = db.Column(db.String(64), nullable=False, index=True)
    answer_digest = db.Column(db.String(64), nullable=False)
    image_png = db.Column(db.LargeBinary, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class PasswordChallenge(db.Model):
    __tablename__ = "password_challenges"

    id = db.Column(db.String(43), primary_key=True)
    browser_hash = db.Column(db.String(64), nullable=False, index=True)
    nonce_digest = db.Column(db.String(64), nullable=False)
    purpose = db.Column(db.String(16), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
