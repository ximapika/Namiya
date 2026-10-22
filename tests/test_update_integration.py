"""Cross-feature checks with the same CSRF boundary used in deployment."""

import re
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.fernet import Fernet
from sqlalchemy import update
from werkzeug.security import generate_password_hash

from app import create_app
from app.bootstrap import bootstrap_database
from app.extensions import db, limiter
from app.models import Letter, User
from app.models_usage import DailyUsage
from app.models_verification import EmailVerification
from app.services.accounts import record_activity

try:
    from tests.auth_helpers import encrypted_password
except ModuleNotFoundError:
    from auth_helpers import encrypted_password


class UpdateIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", {
            "SECRET_KEY": "integration-session-key",
            "EMAIL_LOOKUP_KEY": "integration-email-key",
            "PHONE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "WTF_CSRF_ENABLED": True,
            "PREFERRED_URL_SCHEME": "http",
            "BOOTSTRAP_ADMIN_USERNAME": "", "BOOTSTRAP_ADMIN_PASSWORD": "",
            "EMAIL_RESEND_SECONDS": 0, "EMAIL_HOURLY_LIMIT": 10,
            "DAILY_MESSAGE_LIMIT": 1,
            "MAIL_HOST": "", "MAIL_FROM": "",
        })
        with self.app.app_context():
            bootstrap_database()
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def csrf(self, client, path):
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
        self.assertIsNotNone(match)
        return match.group(1)

    def email_request(self, client, token, purpose, username="student"):
        with patch("app.services.captcha._random_answer", return_value="ABC234"):
            captcha = client.get("/captcha").json
        return client.post("/email-code", data={
            "csrf_token": token, "purpose": purpose, "username": username,
            "email": "integration@stu.pku.edu.cn", "captcha_id": captcha["id"],
            "captcha_answer": "ABC234",
        })

    def test_csrf_registration_login_write_and_recovery_keep_one_daily_budget(self):
        sent = []
        with patch("app.services.email_verification.send_verification_code",
                   side_effect=lambda address, code: sent.append(code)):
            token = self.csrf(self.client, "/register")
            proof = self.email_request(self.client, token, "register")
            self.assertEqual(proof.status_code, 200)
            registered = self.client.post("/register", data={
                "csrf_token": token, "username": "student",
                "email": "integration@stu.pku.edu.cn", "email_code": sent[-1],
                "email_challenge": proof.json["id"],
                **encrypted_password(self.client, "register", "OriginalPassword123"),
            })
            self.assertEqual(registered.status_code, 302)
            token = self.csrf(self.client, "/login")
            logged_in = self.client.post("/login", data={
                "csrf_token": token, "username": "student",
                **encrypted_password(self.client, "login", "OriginalPassword123"),
            })
            self.assertEqual(logged_in.status_code, 302)
            token = self.csrf(self.client, "/write")
            self.assertEqual(self.client.post("/write", data={
                "csrf_token": token, "title": "需要支持", "content": "最近很抑郁，想求助。",
            }).status_code, 302)
            with self.app.app_context():
                old_identity = User.query.one().auth_id
                self.assertEqual(DailyUsage.query.one().message_count, 1)

            recovery = self.app.test_client()
            token = self.csrf(recovery, "/forgot-password")
            proof = self.email_request(recovery, token, "reset")
            self.assertEqual(proof.status_code, 200)
            reset = recovery.post("/forgot-password", data={
                "csrf_token": token, "username": "student",
                "email": "integration@stu.pku.edu.cn", "email_code": sent[-1],
                "email_challenge": proof.json["id"],
                **encrypted_password(recovery, "reset", "ReplacementPassword456"),
            })
            self.assertEqual(reset.status_code, 302)
            self.assertEqual(self.client.get("/inbox").status_code, 302)
            with self.app.app_context():
                self.assertNotEqual(User.query.one().auth_id, old_identity)
            token = self.csrf(recovery, "/login")
            self.assertEqual(recovery.post("/login", data={
                "csrf_token": token, "username": "student",
                **encrypted_password(recovery, "login", "ReplacementPassword456"),
            }).status_code, 302)
            token = self.csrf(recovery, "/write")
            self.assertEqual(recovery.post("/write", data={
                "csrf_token": token, "title": "不能重置额度", "content": "第二条",
            }).status_code, 429)
            with self.app.app_context():
                self.assertEqual(Letter.query.count(), 1)
                self.assertEqual(DailyUsage.query.one().message_count, 1)

    def test_unconfigured_smtp_returns_closed_failure_without_registering_an_account(self):
        token = self.csrf(self.client, "/register")
        response = self.email_request(self.client, token, "register")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("id", response.json)
        self.assertNotIn("integration@", response.text)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 0)
            self.assertIsNotNone(EmailVerification.query.one().consumed_at)

    def test_csrf_rejected_posts_still_consume_the_shared_ip_budget(self):
        limited = create_app("testing", {
            **self.app.config, "RATELIMIT_ENABLED": True,
            "RATELIMIT_STORAGE_URI": "memory://", "IP_REQUEST_RATE_LIMIT": "2 per minute",
        })
        with limited.app_context():
            limiter.reset()
        client = limited.test_client()
        statuses = [client.post(path).status_code
                    for path in ("/email-code", "/register", "/forgot-password")]
        self.assertEqual(statuses, [400, 400, 429])

    def test_password_reset_during_activity_refresh_cannot_upgrade_an_old_session(self):
        with self.app.app_context():
            user = User(username="race-user", password_hash="unused-test-hash",
                        last_active_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2))
            db.session.add(user)
            db.session.commit()
            user_id, old_identity = user.id, user.auth_id
        with self.client.session_transaction() as session:
            session["user_id"], session["auth_id"] = user_id, old_identity

        def reset_immediately_after_activity_commit(user):
            valid = record_activity(user)
            # This independent database commit models another worker completing
            # password reset after activity UPDATE but before session refresh.
            with db.engine.begin() as connection:
                connection.execute(update(User).where(User.id == user_id).values(auth_id="f" * 32))
            return valid

        with patch("app.record_activity", side_effect=reset_immediately_after_activity_commit):
            self.client.get("/inbox")
        with self.client.session_transaction() as session:
            self.assertNotEqual(session.get("auth_id"), "f" * 32,
                                "An old cookie must never inherit the reset identity")
        self.assertEqual(self.client.get("/inbox").status_code, 302)

    def test_login_verified_before_password_reset_cannot_receive_the_new_identity(self):
        with self.app.app_context():
            user = User(username="race-login", password_hash=generate_password_hash("OldPassword123"),
                        last_active_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2))
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        def reset_immediately_after_activity_commit(user):
            valid = record_activity(user)
            with db.engine.begin() as connection:
                connection.execute(update(User).where(User.id == user_id).values(auth_id="e" * 32,
                                   password_hash=generate_password_hash("NewPassword456")))
            return valid

        token = self.csrf(self.client, "/login")
        envelope = encrypted_password(self.client, "login", "OldPassword123")
        with patch("app.routes.auth.record_activity", side_effect=reset_immediately_after_activity_commit):
            self.client.post("/login", data={"csrf_token": token, "username": "race-login", **envelope})
        with self.client.session_transaction() as session:
            self.assertNotEqual(session.get("auth_id"), "e" * 32,
                                "A password checked before reset must not authorize the replacement identity")
        self.assertEqual(self.client.get("/inbox").status_code, 302)
