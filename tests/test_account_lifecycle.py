import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from sqlalchemy import event, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app
from app.bootstrap import bootstrap_database
from app.extensions import db
from app.models import Letter, Reply, ReplyRequest, User
from app.models_challenges import CaptchaChallenge, PasswordChallenge
from app.models_usage import DailyUsage
from app.models_verification import EmailDeliveryLimit, EmailVerification
from app.services.accounts import (
    StaleAccountError, cleanup_inactive_accounts, delete_account, lock_account_identity,
    record_activity, reset_password,
)


class AccountLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", {
            "SECRET_KEY": "lifecycle-test-key",
            "PHONE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "BOOTSTRAP_ADMIN_USERNAME": "", "BOOTSTRAP_ADMIN_PASSWORD": "",
        })
        self.ctx = self.app.app_context()
        self.ctx.push()
        bootstrap_database()
        self.client = self.app.test_client()
        self.now = datetime.now(timezone.utc).replace(tzinfo=None)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def user(self, name, **kwargs):
        user = User(username=name, password_hash=generate_password_hash("OriginalPass123"), **kwargs)
        db.session.add(user)
        db.session.commit()
        return user

    def session_for(self, user, *, legacy=False):
        with self.client.session_transaction() as session:
            session.clear()
            session["user_id"] = user.id
            if not legacy:
                session["auth_id"] = user.auth_id

    def legacy_schema(self):
        db.session.remove()
        db.drop_all()
        db.session.execute(text("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.session.execute(text("""
            INSERT INTO users (username, password_hash, created_at)
            VALUES ('legacy', 'one-way-legacy-hash', '2010-01-01 00:00:00')
        """))
        db.session.commit()
        bootstrap_database()

    def test_old_cookie_without_incarnation_is_invalidated(self):
        user = self.user("alice")
        self.session_for(user, legacy=True)
        response = self.client.get("/inbox")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_legacy_sqlite_id_reuse_cannot_reuse_authenticated_session(self):
        self.legacy_schema()
        old = User.query.one()
        old_id, old_auth = old.id, old.auth_id
        self.session_for(old)
        delete_account(old)
        db.session.commit()
        db.session.expunge_all()
        replacement = self.user("replacement")
        # This verifies the vulnerable legacy layout, not only AUTOINCREMENT.
        self.assertEqual(replacement.id, old_id)
        self.assertNotEqual(replacement.auth_id, old_auth)
        letter = Letter(user_id=replacement.id, title="private", content="replacement-secret")
        db.session.add(letter)
        db.session.commit()
        response = self.client.get("/inbox", follow_redirects=True)
        self.assertNotIn("replacement-secret", response.get_data(as_text=True))
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_account_replacement_during_activity_refresh_is_rejected_in_current_request(self):
        original = self.user("original", last_active_at=self.now - timedelta(days=2))
        user_id = original.id
        self.session_for(original)

        def replace_immediately_after_activity_commit(user):
            valid = record_activity(user)
            with db.engine.begin() as connection:
                connection.execute(User.__table__.delete().where(User.id == user_id))
                connection.execute(User.__table__.insert().values(
                    id=user_id, username="replacement", password_hash="replacement-hash",
                    auth_id="e" * 32, is_admin=False, is_staff=False,
                    last_active_at=self.now,
                ))
                connection.execute(Letter.__table__.insert().values(
                    user_id=user_id, title="replacement-private-title", content="replacement-secret",
                ))
            return valid

        with patch("app.record_activity", side_effect=replace_immediately_after_activity_commit):
            response = self.client.get("/inbox")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("replacement-private-title", response.get_data(as_text=True))
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)
            self.assertNotEqual(session.get("auth_id"), "e" * 32)

    def test_password_reset_revokes_sessions_and_preserves_daily_quota(self):
        user = self.user("alice")
        old_token = user.auth_id
        self.session_for(user)
        db.session.add(DailyUsage(auth_id=user.auth_id, day=self.now.date(), message_count=5))
        db.session.commit()
        user_updates = []

        def capture_user_updates(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("UPDATE users SET"):
                user_updates.append(statement)

        event.listen(db.engine, "before_cursor_execute", capture_user_updates)
        try:
            reset_password(user, "ChangedPassword456")
            db.session.commit()
        finally:
            event.remove(db.engine, "before_cursor_execute", capture_user_updates)
        self.assertEqual(len(user_updates), 1, "ORM must not issue a second unconditional password UPDATE")
        self.assertIn("users.auth_id =", user_updates[0])
        self.assertNotEqual(user.auth_id, old_token)
        self.assertTrue(user.password_hash.startswith("scrypt:"))
        self.assertTrue(check_password_hash(user.password_hash, "ChangedPassword456"))
        self.assertFalse(check_password_hash(user.password_hash, "OriginalPass123"))
        quota = DailyUsage.query.one()
        self.assertEqual((quota.auth_id, quota.message_count), (user.auth_id, 5))
        self.assertEqual(self.client.get("/inbox").status_code, 302)

    def test_stale_password_reset_cannot_overwrite_another_workers_reset(self):
        user = self.user("reset-race")
        db.session.add(DailyUsage(auth_id=user.auth_id, day=self.now.date(), message_count=5))
        db.session.commit()
        user_id, old_identity = user.id, user.auth_id
        winning_hash = generate_password_hash("WinningPassword456", method="scrypt")
        # Keep the first worker's ORM snapshot while a separate transaction
        # rotates the identity and carries its quota to the winning reset.
        with db.engine.begin() as connection:
            connection.execute(User.__table__.update().where(User.id == user_id).values(
                auth_id="f" * 32, password_hash=winning_hash,
            ))
            connection.execute(DailyUsage.__table__.update().where(
                DailyUsage.auth_id == old_identity).values(auth_id="f" * 32))
        with self.assertRaises(StaleAccountError):
            reset_password(user, "StaleProofPassword789")
        db.session.rollback()
        db.session.refresh(user)
        self.assertEqual(user.auth_id, "f" * 32)
        self.assertEqual(user.password_hash, winning_hash)
        self.assertEqual((DailyUsage.query.one().auth_id, DailyUsage.query.one().message_count),
                         ("f" * 32, 5))

    def test_stale_delete_cannot_delete_reused_identity_or_its_content(self):
        original = self.user("deleted-original")
        user_id, original_identity = original.id, original.auth_id
        with db.engine.begin() as connection:
            connection.execute(User.__table__.delete().where(User.id == user_id))
            connection.execute(User.__table__.insert().values(
                id=user_id, username="replacement", password_hash="replacement-hash",
                auth_id="e" * 32, last_active_at=self.now,
            ))
            connection.execute(Letter.__table__.insert().values(
                user_id=user_id, title="replacement-private", content="retain-me",
            ))
            connection.execute(DailyUsage.__table__.insert().values(
                auth_id="e" * 32, day=self.now.date(), message_count=2,
            ))
        self.assertNotEqual(original_identity, "e" * 32)
        with self.assertRaises(StaleAccountError):
            delete_account(original)
        db.session.rollback()
        self.assertEqual(User.query.one().username, "replacement")
        self.assertEqual(Letter.query.one().content, "retain-me")
        self.assertEqual(DailyUsage.query.one().message_count, 2)

    def test_identity_lock_rejects_snapshot_authenticated_before_reset(self):
        user = self.user("binding-race")
        user_id, verified_identity = user.id, user.auth_id
        with db.engine.begin() as connection:
            connection.execute(User.__table__.update().where(User.id == user_id).values(
                auth_id="f" * 32,
            ))
        # Even if an intervening commit/refresh updates the ORM instance, the
        # identity authenticated before the password check must remain fixed.
        db.session.refresh(user)
        self.assertEqual(user.auth_id, "f" * 32)
        with self.assertRaises(StaleAccountError):
            lock_account_identity(user, expected_auth_id=verified_identity)
        db.session.rollback()
        self.assertIsNone(User.query.one().email_hash)

    def test_create_admin_reports_stale_selection_without_granting_role(self):
        user = self.user("ordinary")
        with patch("app.cli.reset_password", side_effect=StaleAccountError("账号状态已变更")):
            response = self.app.test_cli_runner().invoke(args=[
                "create-admin", "--username", "ordinary", "--password", "AdminPassword456",
            ])
        self.assertNotEqual(response.exit_code, 0)
        self.assertIn("账号状态已变更", response.output)
        db.session.refresh(user)
        self.assertFalse(user.is_admin)

    def test_old_schema_migration_is_repeatable_and_grants_90_day_grace(self):
        self.legacy_schema()
        user = User.query.one()
        token, active = user.auth_id, user.last_active_at
        self.assertEqual(len(token), 32)
        self.assertLess(abs((active - self.now).total_seconds()), 10)
        bootstrap_database()
        self.assertEqual((user.auth_id, user.last_active_at), (token, active))
        self.assertEqual(cleanup_inactive_accounts(now=self.now)["accounts"], 0)
        # Legacy tables have equivalent DB-enforced invariants via triggers.
        for statement in (
            "UPDATE users SET auth_id = NULL",
            "UPDATE users SET last_active_at = NULL",
            "UPDATE users SET email_hash = 'digest', email_slot = NULL",
            "UPDATE users SET email_hash = 'digest', email_slot = 4",
        ):
            with self.assertRaises(IntegrityError):
                db.session.execute(text(statement))
            db.session.rollback()

    def test_email_slots_are_database_enforced_on_new_and_legacy_schema(self):
        for legacy in (False, True):
            if legacy:
                self.legacy_schema()
            digest = "a" * 64
            for slot in (1, 2, 3):
                self.user(f"slot-{slot}", email_hash=digest, email_slot=slot)
            with self.assertRaises(IntegrityError):
                self.user("duplicate", email_hash=digest, email_slot=1)
            db.session.rollback()
            with self.assertRaises(IntegrityError):
                self.user("fourth", email_hash=digest, email_slot=4)
            db.session.rollback()

    def test_cleanup_is_dry_by_default_bounded_and_preserves_all_privileged_accounts(self):
        stale = self.now - timedelta(days=91)
        expired = self.user("expired", last_active_at=stale)
        other = self.user("other-expired", last_active_at=stale)
        staff = self.user("staff", is_staff=True, last_active_at=stale)
        admin = self.user("admin", is_admin=True, last_active_at=stale)
        active = self.user("active", last_active_at=self.now)
        letter = Letter(user_id=expired.id, title="remove", content="old-content")
        keep_letter = Letter(user_id=active.id, title="retain", content="current-content")
        db.session.add_all([letter, keep_letter])
        db.session.flush()
        db.session.add_all([
            Reply(letter_id=letter.id, admin_id=staff.id, content="old-reply"),
            ReplyRequest(letter_id=letter.id, staff_id=staff.id),
            Reply(letter_id=keep_letter.id, admin_id=expired.id, content="demoted-user-reply"),
            DailyUsage(auth_id=expired.auth_id, day=self.now.date(), message_count=2),
        ])
        db.session.commit()
        preview = cleanup_inactive_accounts(batch_size=1, now=self.now)
        self.assertEqual(preview["accounts"], 1)
        self.assertEqual(User.query.count(), 5)
        result = cleanup_inactive_accounts(batch_size=1, apply=True, now=self.now)
        self.assertEqual((result["accounts"], result["letters"], result["replies"], result["reply_requests"]),
                         (1, 1, 2, 1))
        self.assertEqual(DailyUsage.query.count(), 0)
        self.assertEqual([row.title for row in Letter.query.all()], ["retain"])
        self.assertEqual(Reply.query.count(), 0)
        self.assertEqual(ReplyRequest.query.count(), 0)
        remaining = {row.username for row in User.query.all()}
        self.assertEqual(remaining, {"other-expired", "staff", "admin", "active"})
        cleanup_inactive_accounts(apply=True, now=self.now)
        remaining = {row.username for row in User.query.all()}
        self.assertEqual(remaining, {"staff", "admin", "active"})

    def test_cleanup_failure_rolls_back_associated_content(self):
        old = self.user("expired", last_active_at=self.now - timedelta(days=100))
        db.session.add(Letter(user_id=old.id, title="must-survive", content="content"))
        db.session.commit()

        def fail_user_delete(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("DELETE FROM users"):
                raise RuntimeError("injected account deletion failure")

        event.listen(db.engine, "before_cursor_execute", fail_user_delete)
        try:
            with self.assertRaises(RuntimeError):
                cleanup_inactive_accounts(apply=True, now=self.now)
        finally:
            event.remove(db.engine, "before_cursor_execute", fail_user_delete)
        self.assertEqual(User.query.count(), 1)
        self.assertEqual(Letter.query.count(), 1)

    def test_activity_updates_are_throttled_and_cli_requires_apply(self):
        user = self.user("active", last_active_at=self.now - timedelta(hours=2))
        record_activity(user, now=self.now)
        self.assertEqual(user.last_active_at, self.now)
        record_activity(user, now=self.now + timedelta(minutes=10))
        self.assertEqual(user.last_active_at, self.now)
        user.last_active_at = self.now - timedelta(days=91)
        db.session.commit()
        runner = self.app.test_cli_runner()
        preview = runner.invoke(args=["cleanup-inactive-accounts"])
        self.assertEqual(preview.exit_code, 0, preview.output)
        self.assertFalse(json.loads(preview.output)["applied"])
        self.assertEqual(User.query.count(), 1)
        applied = runner.invoke(args=["cleanup-inactive-accounts", "--apply"])
        self.assertEqual(applied.exit_code, 0, applied.output)
        self.assertEqual(User.query.count(), 0)
        invalid = runner.invoke(args=["cleanup-inactive-accounts", "--apply", "--days", "30"])
        self.assertNotEqual(invalid.exit_code, 0)

    def test_cleanup_prunes_expired_proofs_but_preserves_live_proofs(self):
        for label, expiration in (("old", self.now - timedelta(hours=1)),
                                  ("live", self.now + timedelta(hours=1))):
            db.session.add(EmailVerification(
                id=label, purpose="register", email_hash="a" * 64,
                code_hash="b" * 64, session_hash="c" * 64, expires_at=expiration,
            ))
            db.session.add(CaptchaChallenge(
                id=label, browser_hash="a" * 64, answer_digest="b" * 64,
                image_png=b"test", expires_at=expiration,
            ))
            db.session.add(PasswordChallenge(
                id=label, browser_hash="a" * 64, nonce_digest="b" * 64,
                purpose="login", expires_at=expiration,
            ))
        db.session.add(EmailDeliveryLimit(
            email_hash="a" * 64, hour_start=self.now - timedelta(days=2),
            last_sent=self.now - timedelta(days=2), sent_count=1,
        ))
        db.session.add(DailyUsage(auth_id="obsolete", day=(self.now - timedelta(days=8)).date(),
                                  message_count=1))
        db.session.commit()
        cleanup_inactive_accounts(apply=False, now=self.now)
        self.assertEqual(EmailVerification.query.count(), 2)
        result = cleanup_inactive_accounts(apply=True, now=self.now)
        self.assertEqual(result["accounts"], 0)
        for model in (EmailVerification, CaptchaChallenge, PasswordChallenge):
            self.assertEqual([row.id for row in model.query.all()], ["live"])
        self.assertEqual(EmailDeliveryLimit.query.count(), 0)
        self.assertEqual(DailyUsage.query.count(), 0)

    def test_file_database_enforces_email_cap_under_concurrent_writers(self):
        with tempfile.TemporaryDirectory(prefix="lifecycle-", dir=self.app.instance_path) as directory:
            file_app = create_app("testing", {
                "SECRET_KEY": "concurrency-test-key",
                "PHONE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                "BOOTSTRAP_ADMIN_USERNAME": "", "BOOTSTRAP_ADMIN_PASSWORD": "",
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{Path(directory) / 'accounts.db'}",
            })
            with file_app.app_context():
                bootstrap_database()
                for slot in (1, 2):
                    self.user(f"existing-{slot}", email_hash="a" * 64, email_slot=slot)
            barrier = threading.Barrier(2)

            def compete(name):
                with file_app.app_context():
                    candidate = User(username=name, password_hash="already-hashed",
                                     email_hash="a" * 64, email_slot=3)
                    db.session.add(candidate)
                    barrier.wait(timeout=5)
                    try:
                        db.session.commit()
                        return True
                    except IntegrityError:
                        db.session.rollback()
                        return False

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(compete, ("contender-one", "contender-two")))
            self.assertEqual(sorted(outcomes), [False, True])
            with file_app.app_context():
                self.assertEqual(User.query.filter_by(email_hash="a" * 64).count(), 3)
                db.session.remove()
                db.engine.dispose()
