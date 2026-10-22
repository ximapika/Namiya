import json
import smtplib
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app
from app.bootstrap import bootstrap_database
from app.extensions import db
from app.models import User
from app.models_verification import EmailDeliveryLimit, EmailVerification
from app.services.accounts import StaleAccountError
from app.services.email_verification import (
    EmailRateLimited, VerificationError, consume_email_verification, email_digest,
    issue_email_verification,
)
from app.services.mail import MailUnavailable, send_verification_code

try:
    from tests.auth_helpers import encrypted_password
except ModuleNotFoundError:
    from auth_helpers import encrypted_password


class EmailVerificationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", {
            "SECRET_KEY": "email-verification-test-session-key",
            "PHONE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "EMAIL_LOOKUP_KEY": "email-index-test-key-that-is-not-the-session-key",
            "BOOTSTRAP_ADMIN_USERNAME": "", "BOOTSTRAP_ADMIN_PASSWORD": "",
            "EMAIL_RESEND_SECONDS": 0, "EMAIL_HOURLY_LIMIT": 100,
        })
        self.ctx = self.app.app_context()
        self.ctx.push()
        bootstrap_database()
        self.client = self.app.test_client()
        self.sent = []
        self.send_patch = patch("app.services.email_verification.send_verification_code",
                                side_effect=lambda address, code: self.sent.append((address, code)))
        self.send_mock = self.send_patch.start()
        self.captcha_patch = patch("app.services.captcha._random_answer", return_value="ABC234")
        self.captcha_patch.start()
        self.now = datetime.now(timezone.utc).replace(tzinfo=None)

    def tearDown(self):
        self.captcha_patch.stop()
        self.send_patch.stop()
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def user(self, username, *, email=None, **roles):
        user = User(username=username, password_hash=generate_password_hash("OriginalPass123"), **roles)
        if email:
            user.email_hash, user.email_slot = email_digest(email), 1
        db.session.add(user)
        db.session.commit()
        return user

    def login_session(self, client, user):
        with client.session_transaction() as session:
            session["user_id"] = user.id
            session["auth_id"] = user.auth_id

    def captcha(self, client):
        response = client.get("/captcha")
        self.assertEqual(response.status_code, 200)
        challenge = response.get_json()
        image = client.get(challenge["image_url"])
        self.assertEqual(image.mimetype, "image/png")
        self.assertTrue(image.data.startswith(b"\x89PNG\r\n\x1a\n"))
        return {"captcha_id": challenge["id"], "captcha_answer": "ABC234"}

    def issue(self, *, client=None, email="anonymous@pku.edu.cn", purpose="register", username=""):
        client = client or self.client
        response = client.post("/email-code", data={
            **self.captcha(client), "email": email, "purpose": purpose, "username": username,
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return {"email": email, "email_challenge": response.get_json()["id"],
                "email_code": self.sent[-1][1]}

    def register(self, username, proof, *, client=None):
        client = client or self.client
        return client.post("/register", data={
            "username": username, **proof, **encrypted_password(client, "register", "GoodPassword123"),
        })

    def reset(self, username, proof, *, client=None):
        client = client or self.client
        return client.post("/forgot-password", data={
            "username": username, **proof, **encrypted_password(client, "reset", "ChangedPassword456"),
        })

    def test_registration_requires_image_challenge_and_exact_pku_domain(self):
        response = self.client.post("/email-code", data={"purpose": "register", "email": "a@pku.edu.cn"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.sent, [])
        for email in ("a@gmail.com", "a@pku.edu.cn.evil.example", "a@evilpku.edu.cn", "a+alias@pku.edu.cn"):
            response = self.client.post("/email-code", data={
                **self.captcha(self.client), "email": email, "purpose": "register",
            })
            self.assertEqual(response.status_code, 400, email)
        self.assertEqual(self.sent, [])
        for index, email in enumerate((" Student@PKU.EDU.CN ", "student@stu.pku.edu.cn")):
            proof = self.issue(email=email)
            self.assertEqual(self.sent[-1][0], email.strip().lower())
            self.assertEqual(self.register(f"student-{index}", proof).status_code, 302)

    def test_each_verified_mailbox_can_register_exactly_three_accounts(self):
        for index in range(3):
            self.assertEqual(self.register(f"account-{index}", self.issue()).status_code, 302)
        denied = self.register("fourth-account", self.issue())
        self.assertEqual(denied.status_code, 400)
        self.assertIn("已绑定 3 个账号", denied.get_data(as_text=True))
        self.assertEqual(User.query.filter_by(email_hash=email_digest("anonymous@pku.edu.cn")).count(), 3)

    def test_registration_proof_is_single_use_and_bound_to_browser_and_address(self):
        proof = self.issue()
        attacker = self.app.test_client()
        self.assertEqual(self.register("stolen", proof, client=attacker).status_code, 400)
        wrong_address = dict(proof, email="someoneelse@pku.edu.cn")
        self.assertEqual(self.register("wrong-address", wrong_address).status_code, 400)
        self.assertEqual(self.register("legitimate", proof).status_code, 302)
        self.assertEqual(self.register("replayed", proof).status_code, 400)
        self.assertEqual([user.username for user in User.query.all()], ["legitimate"])

    def test_verification_proofs_cannot_cross_purpose(self):
        user = self.user("alice", email="anonymous@pku.edu.cn")
        registration = self.issue()
        self.assertEqual(self.reset("alice", registration).status_code, 400)
        reset = self.issue(purpose="reset", username="alice")
        self.assertEqual(self.register("confused-purpose", reset).status_code, 400)
        self.assertEqual(self.reset("alice", reset).status_code, 302)
        self.assertTrue(check_password_hash(user.password_hash, "ChangedPassword456"))

    def test_five_wrong_codes_lock_proof_and_expiry_rejects_correct_code(self):
        proof = self.issue()
        incorrect = dict(proof, email_code="wrong-code")
        for index in range(5):
            self.assertEqual(self.register(f"wrong-{index}", incorrect).status_code, 400)
        record = db.session.get(EmailVerification, proof["email_challenge"])
        db.session.refresh(record)
        self.assertEqual(record.attempts, 5)
        self.assertEqual(self.register("now-correct", proof).status_code, 400)
        expired = self.issue()
        db.session.get(EmailVerification, expired["email_challenge"]).expires_at = self.now - timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.register("expired", expired).status_code, 400)
        self.assertEqual(User.query.count(), 0)

    def test_reset_requires_matching_account_mailbox_and_revokes_every_session(self):
        user = self.user("alice", email="anonymous@pku.edu.cn")
        first, second = self.app.test_client(), self.app.test_client()
        self.login_session(first, user)
        self.login_session(second, user)
        self.assertEqual(first.get("/inbox").status_code, 200)
        self.assertEqual(second.get("/inbox").status_code, 200)
        mismatched = self.issue(email="different@pku.edu.cn", purpose="reset", username="alice")
        self.assertEqual(self.reset("alice", mismatched).status_code, 400)
        self.assertTrue(check_password_hash(user.password_hash, "OriginalPass123"))
        valid = self.issue(purpose="reset", username="alice")
        self.assertEqual(self.reset("alice", valid).status_code, 302)
        self.assertTrue(check_password_hash(user.password_hash, "ChangedPassword456"))
        self.assertEqual(first.get("/inbox").status_code, 302)
        self.assertEqual(second.get("/inbox").status_code, 302)
        self.assertEqual(self.reset("alice", valid).status_code, 400)

    def test_reset_proof_for_one_account_cannot_reset_another_on_same_mailbox(self):
        alice = self.user("alice", email="anonymous@pku.edu.cn")
        bob = User(username="bob", password_hash=generate_password_hash("OriginalPass123"),
                   email_hash=alice.email_hash, email_slot=2)
        db.session.add(bob)
        db.session.commit()
        proof = self.issue(purpose="reset", username="alice")
        self.assertEqual(self.reset("bob", proof).status_code, 400)
        self.assertTrue(check_password_hash(bob.password_hash, "OriginalPass123"))
        self.assertEqual(self.reset("alice", proof).status_code, 302)

    def test_stale_reset_returns_400_and_rolls_back_proof_and_password(self):
        user = self.user("alice", email="anonymous@pku.edu.cn")
        original_hash, original_identity = user.password_hash, user.auth_id
        proof = self.issue(purpose="reset", username="alice")

        def reject_stale_reset(selected, password):
            # The proof was successfully validated in this transaction before
            # the account CAS rejects it. The route must roll that consume back.
            record = db.session.get(EmailVerification, proof["email_challenge"])
            self.assertIsNotNone(record.consumed_at)
            raise StaleAccountError("账号状态已变更")

        with patch("app.routes.auth.reset_password", side_effect=reject_stale_reset):
            response = self.reset("alice", proof)
        self.assertEqual(response.status_code, 400)
        db.session.refresh(user)
        self.assertEqual((user.password_hash, user.auth_id), (original_hash, original_identity))
        record = db.session.get(EmailVerification, proof["email_challenge"], populate_existing=True)
        self.assertIsNone(record.consumed_at)
        self.assertEqual(record.attempts, 0)

    def test_bind_rejects_identity_reset_after_password_check_without_changing_email(self):
        user = self.user("alice", email="original@pku.edu.cn")
        user_id, original_email_hash = user.id, user.email_hash
        self.login_session(self.client, user)
        proof = self.issue(purpose="bind_email")
        envelope = encrypted_password(self.client, "bind_email", "OriginalPass123")

        def reset_identity_after_password_check(password_hash, password):
            valid = check_password_hash(password_hash, password)
            self.assertTrue(valid)
            with db.engine.begin() as connection:
                connection.execute(User.__table__.update().where(User.id == user_id).values(
                    auth_id="e" * 32,
                ))
            return valid

        with patch("app.routes.auth.check_password_hash", side_effect=reset_identity_after_password_check):
            response = self.client.post("/account/email", data={**proof, **envelope})
        self.assertEqual(response.status_code, 400)
        db.session.refresh(user)
        self.assertEqual(user.auth_id, "e" * 32)
        self.assertEqual((user.email_hash, user.email_slot), (original_email_hash, 1))
        record = db.session.get(EmailVerification, proof["email_challenge"], populate_existing=True)
        self.assertIsNone(record.consumed_at)
        self.assertEqual(record.attempts, 0)

    def test_existing_account_email_binding_requires_login_password_and_own_proof(self):
        user = self.user("legacy")
        response = self.client.post("/email-code", data={
            **self.captcha(self.client), "email": "anonymous@pku.edu.cn", "purpose": "bind_email",
        })
        self.assertEqual(response.status_code, 401)
        self.login_session(self.client, user)
        proof = self.issue(purpose="bind_email")
        wrong = self.client.post("/account/email", data={
            **proof, **encrypted_password(self.client, "bind_email", "WrongPassword123"),
        })
        self.assertEqual(wrong.status_code, 400)
        self.assertIsNone(user.email_hash)
        valid = self.client.post("/account/email", data={
            **proof, **encrypted_password(self.client, "bind_email", "OriginalPass123"),
        })
        self.assertEqual(valid.status_code, 302)
        self.assertEqual(user.email_hash, email_digest("anonymous@pku.edu.cn"))
        self.assertEqual(user.email_slot, 1)

    def test_mailbox_delivery_limits_span_purposes_and_sessions(self):
        self.app.config["EMAIL_HOURLY_LIMIT"] = 2
        self.issue()
        other = self.app.test_client()
        self.issue(client=other, purpose="reset", username="unknown")
        blocked = self.client.post("/email-code", data={
            **self.captcha(self.client), "email": "anonymous@pku.edu.cn", "purpose": "register",
        })
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(len(self.sent), 2)
        record = EmailDeliveryLimit.query.one()
        self.assertEqual(record.sent_count, 2)
        record.hour_start -= timedelta(hours=1)
        record.last_sent -= timedelta(hours=1)
        db.session.commit()
        self.issue()
        db.session.refresh(record)
        self.assertEqual(record.sent_count, 1)

    def test_smtp_failure_consumes_proof_and_returns_service_unavailable(self):
        delivered = []

        def fail(address, code):
            delivered.append((address, code))
            raise MailUnavailable("邮件服务暂不可用")

        self.send_mock.side_effect = fail
        response = self.client.post("/email-code", data={
            **self.captcha(self.client), "email": "anonymous@pku.edu.cn", "purpose": "register",
        })
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("id", response.get_json())
        record = EmailVerification.query.one()
        self.assertIsNotNone(record.consumed_at)
        proof = {"email": delivered[0][0], "email_code": delivered[0][1], "email_challenge": record.id}
        self.assertEqual(self.register("undelivered", proof).status_code, 400)
        self.assertEqual(User.query.count(), 0)

    def test_smtp_requires_encryption_and_does_not_log_recipient_on_failure(self):
        with self.assertRaises(MailUnavailable):
            send_verification_code("private-person@pku.edu.cn", "123456")
        self.app.config.update(MAIL_HOST="smtp.example", MAIL_FROM="robot@example.test",
                               MAIL_USE_SSL=False, MAIL_USE_TLS=False)
        with self.assertRaises(MailUnavailable):
            send_verification_code("private-person@pku.edu.cn", "123456")
        self.app.config["MAIL_USE_SSL"] = True
        with patch("app.services.mail.smtplib.SMTP_SSL", side_effect=smtplib.SMTPException(
                "private-person@pku.edu.cn secret-password")):
            with self.assertLogs(self.app.logger, level="WARNING") as logs:
                with self.assertRaises(MailUnavailable) as error:
                    send_verification_code("private-person@pku.edu.cn", "123456")
        self.assertNotIn("private-person", str(error.exception) + " ".join(logs.output))
        self.assertNotIn("secret-password", " ".join(logs.output))

    def test_email_and_code_are_absent_from_database_cookie_and_admin_pages(self):
        address = "private-person@pku.edu.cn"
        proof = self.issue(email=address)
        self.assertEqual(self.register("anonymous-user", proof).status_code, 302)
        connection = db.session.connection().connection.driver_connection
        dump = "\n".join(connection.iterdump())
        self.assertNotIn(address, dump)
        self.assertNotIn("'" + proof["email_code"] + "'", dump)
        self.assertNotIn("GoodPassword123", dump)
        with self.client.session_transaction() as session:
            self.assertNotIn(address, json.dumps(dict(session)))
        user = User.query.filter_by(username="anonymous-user").one()
        admin = self.user("manager", is_admin=True)
        self.login_session(self.client, admin)
        page = self.client.get("/admin/staff", query_string={"selected": user.username})
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(address, page.get_data(as_text=True))
        self.assertNotIn(user.email_hash, page.get_data(as_text=True))

    def test_encrypted_successful_login_reaches_inbox(self):
        user = self.user("alice")
        user.last_active_at = self.now - timedelta(days=100)
        db.session.commit()
        response = self.client.post("/login", data={
            "username": "alice", **encrypted_password(self.client, "login", "OriginalPass123"),
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/inbox")
        db.session.refresh(user)
        self.assertGreaterEqual(user.last_active_at, self.now)
        self.assertEqual(self.client.get("/inbox").status_code, 200)

    def test_file_database_consumes_proof_and_reserves_delivery_once_under_concurrency(self):
        with tempfile.TemporaryDirectory(prefix="email-race-", dir=self.app.instance_path) as directory:
            file_app = create_app("testing", {
                "SECRET_KEY": "concurrent-email-test-key",
                "PHONE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                "EMAIL_LOOKUP_KEY": "concurrent-email-lookup-key",
                "BOOTSTRAP_ADMIN_USERNAME": "", "BOOTSTRAP_ADMIN_PASSWORD": "",
                "EMAIL_RESEND_SECONDS": 0, "EMAIL_HOURLY_LIMIT": 1,
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{Path(directory) / 'email.db'}",
            })
            with file_app.app_context():
                bootstrap_database()
                client = file_app.test_client()
                proof = self.issue(client=client)
                with client.session_transaction() as browser_session:
                    session_token = browser_session["email_verification_session"]
            consume_barrier = threading.Barrier(2)

            def consume_once(_):
                with file_app.test_request_context():
                    session["email_verification_session"] = session_token
                    consume_barrier.wait(timeout=5)
                    try:
                        consume_email_verification(proof["email_challenge"], proof["email_code"],
                                                   proof["email"], "register")
                        db.session.commit()
                        return True
                    except VerificationError:
                        db.session.rollback()
                        return False

            with ThreadPoolExecutor(max_workers=2) as executor:
                consumed = list(executor.map(consume_once, range(2)))
            self.assertEqual(sorted(consumed), [False, True])
            reserve_barrier = threading.Barrier(2)

            def reserve_once(purpose):
                with file_app.test_request_context():
                    reserve_barrier.wait(timeout=5)
                    try:
                        issue_email_verification("race@pku.edu.cn", purpose)
                        return True
                    except EmailRateLimited:
                        return False

            with ThreadPoolExecutor(max_workers=2) as executor:
                reserved = list(executor.map(reserve_once, ("register", "reset")))
            self.assertEqual(sorted(reserved), [False, True])
            with file_app.app_context():
                row = EmailDeliveryLimit.query.filter_by(email_hash=email_digest("race@pku.edu.cn")).one()
                self.assertEqual(row.sent_count, 1)
                self.assertEqual(EmailVerification.query.filter_by(email_hash=row.email_hash).count(), 1)
                db.session.remove()
                db.engine.dispose()
