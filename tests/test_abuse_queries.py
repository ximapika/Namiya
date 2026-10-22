import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from types import SimpleNamespace

from cryptography.fernet import Fernet
from flask import g, template_rendered
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.bootstrap import bootstrap_database
from app.extensions import db, limiter
from app.models import Letter, Reply, ReplyRequest, User
from app.models_usage import DailyUsage
from app.services.accounts import reset_password
from app.services.quotas import consume_daily_message
from app.services.rate_limits import user_rate_key


class AbuseAndQueryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="namiya-abuse-")
        self.app = create_app("testing", {
            "SECRET_KEY": "abuse-tests-session-key",
            "PHONE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{self.directory.name}/test.db",
            "BOOTSTRAP_ADMIN_USERNAME": "", "BOOTSTRAP_ADMIN_PASSWORD": "",
            "DAILY_MESSAGE_LIMIT": 5, "PAGE_SIZE": 20,
            "TRUST_PROXY": False,
        })
        self.context = self.app.app_context()
        self.context.push()
        bootstrap_database()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.engine.dispose()
        self.context.pop()
        self.directory.cleanup()

    def user(self, name="alice", **roles):
        user = User(username=name, password_hash="not-a-login-credential", **roles)
        db.session.add(user)
        db.session.commit()
        return user

    def login(self, user, client=None):
        with (client or self.client).session_transaction() as session:
            session["user_id"] = user.id
            session["auth_id"] = user.auth_id

    def render_context(self, path):
        captured = []

        def record(sender, template, context, **extra):
            captured.append(context)

        with template_rendered.connected_to(record, self.app):
            response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return response, captured[-1]

    def test_daily_limit_combines_letters_and_phone_and_ignores_invalid_input(self):
        user = self.user()
        self.login(user)
        self.app.config["DAILY_MESSAGE_LIMIT"] = 2
        self.client.post("/write", data={"title": "missing body"})
        self.assertEqual(DailyUsage.query.count(), 0)
        self.assertEqual(self.client.post("/write", data={"title": "来信", "content": "求助"}).status_code, 302)
        self.assertEqual(self.client.post("/write", data={
            "type": "phone", "phone_title": "来电", "phone_content": "失眠",
            "phone_number": "13800138000", "preferred_call_time": "明天",
        }).status_code, 302)
        self.assertEqual(self.client.post("/write", data={"title": "超额", "content": "求助"}).status_code, 429)
        self.assertEqual(Letter.query.count(), 2)
        self.assertEqual(DailyUsage.query.one().message_count, 2)

    def test_quota_initializes_from_existing_messages_and_rolls_back_with_insert(self):
        user = self.user()
        self.app.config["DAILY_MESSAGE_LIMIT"] = 1
        self.assertTrue(consume_daily_message(user))
        db.session.add(Letter(user_id=user.id, title=None, content="invalid"))
        with self.assertRaises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        self.assertEqual(DailyUsage.query.count(), 0)
        db.session.add(Letter(user_id=user.id, title="already sent", content="help"))
        db.session.commit()
        self.assertFalse(consume_daily_message(user))
        db.session.rollback()

    def test_quota_resets_at_shanghai_midnight_and_survives_password_reset(self):
        user = self.user()
        self.app.config["DAILY_MESSAGE_LIMIT"] = 1
        before = datetime(2026, 10, 14, 15, 59, tzinfo=timezone.utc)
        after = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        self.assertTrue(consume_daily_message(user, now=before))
        db.session.commit()
        reset_password(user, "new-test-password")
        db.session.commit()
        self.assertFalse(consume_daily_message(user, now=before))
        db.session.rollback()
        self.assertTrue(consume_daily_message(user, now=after))
        db.session.commit()
        self.assertEqual([str(row.day) for row in DailyUsage.query.order_by(DailyUsage.day)],
                         ["2026-10-14", "2026-10-15"])

    def test_concurrent_submissions_cannot_exceed_daily_limit(self):
        user = self.user()
        user_id, auth_id = user.id, user.auth_id
        db.session.remove()
        barrier = threading.Barrier(10)

        def submit(index):
            client = self.app.test_client()
            with client.session_transaction() as session:
                session["user_id"], session["auth_id"] = user_id, auth_id
            barrier.wait(timeout=10)
            return client.post("/write", data={"title": f"并发{index}", "content": "求助"}).status_code

        with ThreadPoolExecutor(max_workers=10) as executor:
            statuses = list(executor.map(submit, range(10)))
        self.assertEqual(statuses.count(302), 5, statuses)
        self.assertEqual(statuses.count(429), 5, statuses)
        self.assertEqual(Letter.query.count(), 5)
        self.assertEqual(DailyUsage.query.one().message_count, 5)

    def test_stale_inflight_identity_cannot_start_a_new_quota_after_password_reset(self):
        user = self.user()
        stale = SimpleNamespace(id=user.id, auth_id=user.auth_id)
        self.assertTrue(consume_daily_message(user))
        db.session.commit()
        reset_password(user, "different-test-password")
        db.session.commit()
        self.assertFalse(consume_daily_message(stale))
        db.session.rollback()
        self.assertEqual(DailyUsage.query.count(), 1)

    def test_inbox_pagination_is_bounded_stable_and_private(self):
        alice, bob = self.user(), self.user("bob")
        db.session.add_all([Letter(user_id=alice.id, title=f"letter-{n:03}", content="PRIVATE-BODY")
                            for n in range(55)])
        db.session.add(Letter(user_id=bob.id, title="BOB-PRIVATE", content="BOB-BODY"))
        db.session.commit()
        self.login(alice)
        response, context = self.render_context("/inbox?per_page=999")
        self.assertEqual(len(context["letters"]), 50)
        first_ids = {letter.id for letter in context["letters"]}
        self.assertNotIn("PRIVATE-BODY", response.text)
        self.assertNotIn("BOB-PRIVATE", response.text)
        _, context = self.render_context("/inbox?per_page=999&page=2")
        self.assertEqual(len(context["letters"]), 5)
        self.assertFalse(first_ids & {letter.id for letter in context["letters"]})
        for query in ("page=-1", "page=no", "per_page=0"):
            self.assertEqual(self.client.get(f"/inbox?{query}").status_code, 400)
        self.assertEqual(self.client.get("/inbox?page=999999999999999999999999").status_code, 404)
        bob_letter = Letter.query.filter_by(user_id=bob.id).one()
        self.assertEqual(self.client.get(f"/letter/{bob_letter.id}?reply_page=2").status_code, 302)

    def test_admin_filters_before_pagination_and_lists_only_summary_columns(self):
        admin, user = self.user("admin", is_admin=True), self.user()
        letters = [Letter(user_id=user.id, title=f"topic-{n}", content="PRIVATE-BODY") for n in range(60)]
        db.session.add_all(letters)
        db.session.flush()
        db.session.add_all([Reply(letter_id=letter.id, admin_id=admin.id, content="reply") for letter in letters[:35]])
        db.session.commit()
        self.login(admin)
        statements = []

        def record(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        event.listen(db.engine, "before_cursor_execute", record)
        try:
            response, context = self.render_context("/admin?status=pending&per_page=10")
        finally:
            event.remove(db.engine, "before_cursor_execute", record)
        self.assertEqual(context["pagination"].total, 25)
        self.assertEqual(len(context["letters"]), 10)
        self.assertTrue(all(letter.reply_count == 0 for letter in context["letters"]))
        self.assertEqual((context["total"], context["replied"], context["pending"]), (60, 35, 25))
        self.assertNotIn("PRIVATE-BODY", response.text)
        self.assertFalse(any("letters.content" in statement for statement in statements))
        self.assertLessEqual(len(statements), 8)
        _, detail = self.render_context(f"/admin/letter/{letters[0].id}?per_page=10")
        self.assertEqual(len(detail["user_history"]), 10)
        self.assertEqual(detail["history_page"].total, 59)

    def test_account_queries_are_constant_with_page_size_and_exclude_private_columns(self):
        admin = self.user("admin", is_admin=True)
        db.session.add_all([User(username=f"account-{n}", password_hash="SECRET-HASH") for n in range(55)])
        db.session.commit()
        self.login(admin)
        counts = []
        for size in (1, 50):
            statements = []

            def record(connection, cursor, statement, parameters, context, executemany):
                if statement.lstrip().upper().startswith("SELECT"):
                    statements.append(statement)

            db.session.expire_all()
            event.listen(db.engine, "before_cursor_execute", record)
            try:
                response, context = self.render_context(f"/admin/staff?per_page={size}")
            finally:
                event.remove(db.engine, "before_cursor_execute", record)
            counts.append(len(statements))
            self.assertEqual(len(context["account_list"]), size)
            self.assertNotIn("SECRET-HASH", response.text)
            list_selects = [statement for statement in statements if "AS letter_count" in statement]
            self.assertTrue(list_selects)
            self.assertFalse(any("password_hash" in sql or "email_hash" in sql for sql in list_selects))
        self.assertEqual(counts[0], counts[1])
        self.assertLessEqual(counts[0], 7)

    def test_replies_and_staff_requests_have_independent_pagination(self):
        admin, user = self.user("admin", is_admin=True), self.user()
        letter = Letter(user_id=user.id, title="title", content="content")
        db.session.add(letter)
        db.session.flush()
        db.session.add_all([Reply(letter_id=letter.id, admin_id=admin.id, content=f"reply-{n}") for n in range(53)])
        staff = [User(username=f"staff-{n}", password_hash="hash", is_staff=True) for n in range(53)]
        db.session.add_all(staff)
        db.session.flush()
        db.session.add_all([ReplyRequest(letter_id=letter.id, staff_id=person.id) for person in staff])
        db.session.commit()
        self.login(user)
        _, detail = self.render_context(f"/letter/{letter.id}?per_page=999&reply_page=2")
        self.assertEqual(len(detail["replies"]), 3)
        self.login(admin)
        _, dashboard = self.render_context("/admin?per_page=999&requests_page=2")
        self.assertEqual(len(dashboard["pending_requests"]), 3)
        _, accounts = self.render_context("/admin/staff?per_page=999&staff_page=2")
        self.assertEqual(len(accounts["staff_list"]), 3)

    def test_user_rate_key_is_stable_across_ips_and_ignores_forged_headers(self):
        user = self.user()
        with self.app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"}):
            g.current_user = None
            self.assertEqual(user_rate_key(), "ip:127.0.0.1")
            g.current_user = user
            key = user_rate_key()
        with self.app.test_request_context(environ_base={"REMOTE_ADDR": "5.6.7.8"}):
            g.current_user = user
            self.assertEqual(user_rate_key(), key)

    def test_write_limit_follows_account_across_ips_and_separates_shared_ip_users(self):
        alice, bob = self.user(), self.user("bob")
        identities = [(person.id, person.auth_id) for person in (alice, bob)]
        limited = create_app("testing", {
            **self.app.config, "RATELIMIT_ENABLED": True,
            "RATELIMIT_STORAGE_URI": "memory://", "WRITE_RATE_LIMIT": "1 per minute",
            "USER_REQUEST_RATE_LIMIT": "100 per minute", "IP_REQUEST_RATE_LIMIT": "100 per minute",
        })
        with limited.app_context():
            limiter.reset()
        clients = [limited.test_client(), limited.test_client()]
        for client, (user_id, auth_id) in zip(clients, identities):
            with client.session_transaction() as session:
                session["user_id"], session["auth_id"] = user_id, auth_id
        payload = {"title": "写信", "content": "需要帮助"}
        first = clients[0].post("/write", data=payload, environ_base={"REMOTE_ADDR": "10.0.0.1"})
        second = clients[0].post("/write", data=payload, environ_base={"REMOTE_ADDR": "10.0.0.2"})
        other_user = clients[1].post("/write", data=payload, environ_base={"REMOTE_ADDR": "10.0.0.1"})
        self.assertEqual((first.status_code, second.status_code, other_user.status_code), (302, 429, 302))

    def test_global_user_limit_spans_dynamic_endpoints_and_ips(self):
        user = self.user()
        identity = user.id, user.auth_id
        limited = create_app("testing", {
            **self.app.config, "RATELIMIT_ENABLED": True,
            "RATELIMIT_STORAGE_URI": "memory://",
            "USER_REQUEST_RATE_LIMIT": "3 per minute", "IP_REQUEST_RATE_LIMIT": "100 per minute",
        })
        with limited.app_context():
            limiter.reset()
        client = limited.test_client()
        with client.session_transaction() as session:
            session["user_id"], session["auth_id"] = identity
        statuses = [client.get(path, environ_base={"REMOTE_ADDR": f"10.0.0.{index}"}).status_code
                    for index, path in enumerate(("/inbox", "/write", "/", "/inbox"), start=1)]
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertEqual(statuses[3], 429)

    def test_global_ip_limit_spans_anonymous_routes_and_ignores_spoofed_forwarding(self):
        limited = create_app("testing", {
            **self.app.config, "RATELIMIT_ENABLED": True,
            "RATELIMIT_STORAGE_URI": "memory://",
            "USER_REQUEST_RATE_LIMIT": "60 per minute", "IP_REQUEST_RATE_LIMIT": "3 per minute",
        })
        with limited.app_context():
            limiter.reset()
        client = limited.test_client()
        with client.get("/static/js/write.js") as response:
            self.assertEqual(response.status_code, 200)
        statuses = [client.get(path, headers={"X-Forwarded-For": f"10.0.0.{index}"}).status_code
                    for index, path in enumerate(("/", "/login", "/register", "/"), start=1)]
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertEqual(statuses[3], 429)
