import os
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app
from app.bootstrap import bootstrap_database
from app.extensions import db
from app.models import Letter, Reply, User
from config import BASE_DIR, build_app_config


class WorryShopAppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            "testing",
            test_config={
                "BOOTSTRAP_ADMIN_USERNAME": "",
                "BOOTSTRAP_ADMIN_PASSWORD": "",
            },
        )
        self.ctx = self.app.app_context()
        self.ctx.push()
        bootstrap_database()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_register_login_and_encrypted_phone_submission(self):
        response = self.client.post(
            "/register",
            data={
                "username": "alice",
                "password": "Password123",
                "confirm": "Password123",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("注册成功", response.get_data(as_text=True))

        response = self.client.post(
            "/login",
            data={"username": "alice", "password": "Password123"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("我的信箱", response.get_data(as_text=True))

        response = self.client.post(
            "/write",
            data={
                "type": "phone",
                "phone_title": "想聊聊最近的压力",
                "phone_content": "最近总是睡不好。",
                "phone_number": "13800138000",
                "preferred_call_time": "今晚 8 点后",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("来电登记已成功提交", response.get_data(as_text=True))

        user = User.query.filter_by(username="alice").first()
        letter = Letter.query.filter_by(user_id=user.id).first()
        self.assertIsNotNone(letter)
        self.assertEqual(letter.phone_number, "13800138000")
        self.assertNotEqual(letter.phone_number_raw, "13800138000")
        self.assertEqual(letter.preferred_call_time, "今晚 8 点后")
        self.assertNotEqual(letter.preferred_call_time_raw, "今晚 8 点后")

    def test_admin_dashboard_and_letter_detail(self):
        admin = User(
            username="admin",
            password_hash=generate_password_hash("AdminPass123"),
            is_admin=True,
        )
        user = User(
            username="alice",
            password_hash=generate_password_hash("Password123"),
        )
        db.session.add_all([admin, user])
        db.session.commit()

        letter = Letter(user_id=user.id, title="测试来信", content="需要一点帮助", type="letter")
        db.session.add(letter)
        db.session.commit()

        reply = Reply(letter_id=letter.id, admin_id=admin.id, content="我们在。")
        db.session.add(reply)
        db.session.commit()

        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "AdminPass123"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("信件管理台", response.get_data(as_text=True))
        self.assertIn("测试来信", response.get_data(as_text=True))

        detail = self.client.get(f"/admin/letter/{letter.id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("测试来信", detail.get_data(as_text=True))

    def test_database_url_is_resolved_from_environment_at_app_creation_time(self):
        with patch.dict(
            os.environ,
            {
                "DATABASE_URL": "sqlite:///tmp/runtime-env.db",
                "APP_ENV": "development",
            },
            clear=False,
        ):
            app = create_app(
                "development",
                test_config={
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                    "BOOTSTRAP_ADMIN_PASSWORD": "",
                },
            )

        expected = f"sqlite:///{(BASE_DIR / Path('tmp/runtime-env.db')).resolve()}"
        self.assertEqual(app.config["SQLALCHEMY_DATABASE_URI"], expected)

    def test_production_requires_database_url(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "DATABASE_URL is required in production"):
                build_app_config("production")

    def test_bootstrap_admin_password_from_environment_updates_existing_user(self):
        with patch.dict(
            os.environ,
            {
                "BOOTSTRAP_ADMIN_USERNAME": "bootstrap-admin",
                "BOOTSTRAP_ADMIN_PASSWORD": "EnvPass123",
            },
            clear=False,
        ):
            app = create_app("testing")

        ctx = app.app_context()
        ctx.push()
        try:
            db.create_all()
            user = User(
                username="bootstrap-admin",
                password_hash=generate_password_hash("OldPass123"),
                is_admin=False,
                is_staff=True,
            )
            db.session.add(user)
            db.session.commit()

            bootstrap_database()

            refreshed = User.query.filter_by(username="bootstrap-admin").first()
            self.assertIsNotNone(refreshed)
            self.assertTrue(refreshed.is_admin)
            self.assertFalse(refreshed.is_staff)
            self.assertTrue(check_password_hash(refreshed.password_hash, "EnvPass123"))
        finally:
            db.session.remove()
            db.drop_all()
            ctx.pop()


if __name__ == "__main__":
    unittest.main()
