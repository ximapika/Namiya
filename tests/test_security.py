import unittest

from cryptography.fernet import Fernet, InvalidToken
from flask import request
from werkzeug.security import generate_password_hash

from app import create_app
from app.bootstrap import bootstrap_database
from app.extensions import db, phone_cipher
from app.models import Letter, Reply, User


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', {
            'SECRET_KEY': 'isolated-test-session-key',
            'PHONE_ENCRYPTION_KEY': Fernet.generate_key().decode(),
            'BOOTSTRAP_ADMIN_USERNAME': '', 'BOOTSTRAP_ADMIN_PASSWORD': '',
            'TRUST_PROXY': False, 'PREFERRED_URL_SCHEME': 'http',
        })
        self.ctx = self.app.app_context()
        self.ctx.push()
        bootstrap_database()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def user(self, name, **roles):
        user = User(username=name, password_hash=generate_password_hash('TestPassword123'), **roles)
        db.session.add(user)
        db.session.commit()
        return user

    def login(self, user):
        with self.client.session_transaction() as session:
            session['user_id'] = user.id

    def test_redirects_reject_external_and_browser_normalized_urls(self):
        for target in ('https://evil.example', '//evil.example', '/\\evil.example',
                       '/\n/evil.example', 'javascript:alert(1)'):
            response = self.client.post('/theme', data={'next': target})
            self.assertEqual(response.headers['Location'], '/')
        response = self.client.post('/theme', data={'next': '/inbox?x=1'})
        self.assertEqual(response.headers['Location'], '/inbox?x=1')

    def test_forged_proxy_headers_do_not_change_ip_scheme_or_host(self):
        @self.app.route('/probe')
        def probe():
            return {'ip': request.remote_addr, 'scheme': request.scheme, 'host': request.host}
        response = self.client.get('/probe', headers={
            'X-Forwarded-For': '1.2.3.4', 'X-Forwarded-Proto': 'https',
            'X-Forwarded-Host': 'evil.example',
        })
        self.assertEqual(response.json, {'ip': '127.0.0.1', 'scheme': 'http', 'host': 'localhost'})

    def test_csrf_protects_logout_and_mutations(self):
        user = self.user('alice')
        self.login(user)
        self.app.config['WTF_CSRF_ENABLED'] = True
        self.assertEqual(self.client.get('/logout').status_code, 405)
        for path in ('/logout', '/write', '/theme', '/admin/grant_staff'):
            self.assertEqual(self.client.post(path).status_code, 400)
        with self.client.session_transaction() as session:
            self.assertEqual(session['user_id'], user.id)
        page = self.client.get('/inbox').get_data(as_text=True)
        import re
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        self.assertEqual(self.client.post('/logout', data={'csrf_token': token}).status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn('user_id', session)

    def test_other_customer_cannot_read_letter_or_mutate_roles(self):
        alice, bob = self.user('alice'), self.user('bob')
        letter = Letter(user_id=alice.id, title='private-title', content='private-content')
        db.session.add(letter)
        db.session.commit()
        self.login(bob)
        for path in (f'/letter/{letter.id}', f'/admin/letter/{letter.id}', '/admin/staff'):
            response = self.client.get(path, follow_redirects=True)
            self.assertNotIn('private-content', response.get_data(as_text=True))
        self.client.post('/admin/grant_staff', data={'username': 'bob', 'action': 'grant'})
        self.assertFalse(db.session.get(User, bob.id).is_staff)

    def test_staff_requires_reply_approval_and_revocation_takes_effect(self):
        alice, staff = self.user('alice'), self.user('staff', is_staff=True)
        letter = Letter(user_id=alice.id, title='private-title', content='private-content')
        db.session.add(letter)
        db.session.commit()
        self.login(staff)
        self.client.post(f'/admin/letter/{letter.id}', data={'action': 'reply', 'content': 'unauthorized'})
        self.assertEqual(Reply.query.count(), 0)
        staff.is_staff = False
        db.session.commit()
        response = self.client.get('/admin', follow_redirects=True)
        self.assertNotIn('private-content', response.get_data(as_text=True))

    def test_cipher_is_scoped_to_app_and_wrong_key_aborts_migration(self):
        alice = self.user('alice')
        ciphertext = phone_cipher.encrypt('13800138000')
        other = create_app('testing', {
            'PHONE_ENCRYPTION_KEY': Fernet.generate_key().decode(),
            'BOOTSTRAP_ADMIN_USERNAME': '', 'BOOTSTRAP_ADMIN_PASSWORD': '',
        })
        self.assertEqual(phone_cipher.decrypt(ciphertext), '13800138000')
        with other.app_context():
            with self.assertRaises(InvalidToken):
                phone_cipher.decrypt(ciphertext)
        # Legacy unprefixed token also authenticates; wrong-key values must
        # never be treated as plaintext and wrapped in another encryption layer.
        legacy = Fernet(Fernet.generate_key()).encrypt(b'13900139000').decode()
        good = Letter(user_id=alice.id, title='legacy', phone_number_raw='13800138000')
        bad = Letter(user_id=alice.id, title='wrong-key', phone_number_raw=legacy)
        db.session.add_all([good, bad])
        db.session.commit()
        with self.assertRaises(InvalidToken):
            bootstrap_database()
        db.session.rollback()
        self.assertEqual(good.phone_number_raw, '13800138000')
        self.assertEqual(bad.phone_number_raw, legacy)

    def test_legacy_migration_is_idempotent_and_handles_time_without_phone(self):
        alice = self.user('alice')
        legacy = phone_cipher.encrypt('13800138000').removeprefix('enc:v1:')
        letter = Letter(user_id=alice.id, title='legacy', phone_number_raw=legacy,
                        preferred_call_time_raw='tomorrow')
        time_only = Letter(user_id=alice.id, title='time', preferred_call_time_raw='tonight')
        db.session.add_all([letter, time_only])
        db.session.commit()
        bootstrap_database()
        first = time_only.preferred_call_time_raw
        bootstrap_database()
        self.assertEqual(time_only.preferred_call_time_raw, first)
        self.assertEqual(time_only.preferred_call_time, 'tonight')
        self.assertEqual(letter.phone_number_raw, legacy)
        self.assertEqual(letter.phone_number, '13800138000')

    def test_private_responses_are_not_cached_and_content_is_escaped(self):
        alice = self.user('alice')
        letter = Letter(user_id=alice.id, title='test', content='<script>alert(1)</script>')
        db.session.add(letter)
        db.session.commit()
        self.login(alice)
        response = self.client.get(f'/letter/{letter.id}')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn('<script>alert(1)</script>', response.get_data(as_text=True))
        self.assertIn('&lt;script&gt;', response.get_data(as_text=True))
