import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, jsonify, request
from PIL import Image
from sqlalchemy import event

from app.extensions import db, limiter
from app.models_challenges import CaptchaChallenge, PasswordChallenge
from app.routes.challenges import challenges_bp
from app.services.captcha import utcnow, verify_captcha
from app.services.password_transport import (
    PasswordTransportError, decrypt_password_submission, init_password_transport,
)

try:
    from tests.auth_helpers import encrypted_password, encrypt_challenge
except ModuleNotFoundError:
    from auth_helpers import encrypted_password, encrypt_challenge


class ChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A real shared file also checks the multi-worker deployment contract.
        directory = Path(__file__).resolve().parents[1] / "instance"
        directory.mkdir(exist_ok=True)
        cls.key_dir = tempfile.TemporaryDirectory(prefix="challenge-tests-", dir=directory)
        cls.key_file = Path(cls.key_dir.name) / "key.pem"
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.key_file.write_bytes(cls.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        cls.key_file.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.key_dir.cleanup()

    def setUp(self):
        self.app = self.make_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()
        self.client = self.app.test_client()

    def make_app(self, **overrides):
        app = Flask(__name__)
        app.config.update(
            TESTING=True, SECRET_KEY="challenge-test-session-key",
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            PASSWORD_TRANSPORT_PRIVATE_KEY_FILE=str(self.key_file),
            RATELIMIT_ENABLED=False, RATELIMIT_STORAGE_URI="memory://",
        )
        app.config.update(overrides)
        db.init_app(app)
        limiter.init_app(app)
        init_password_transport(app)
        app.register_blueprint(challenges_bp)

        @app.post("/consume/<purpose>")
        def consume(purpose):
            try:
                password, confirm = decrypt_password_submission(purpose)
                # Tests return a digest, never a decrypted credential.
                return jsonify(digest=hashlib.sha256(password.encode()).hexdigest(),
                               confirmation_matches=(password == confirm))
            except PasswordTransportError:
                return {"error": "invalid envelope"}, 400

        @app.post("/verify-captcha")
        def verify():
            return {"valid": verify_captcha(request.form.get("captcha_id"), request.form.get("captcha_answer"))}

        return app

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def captcha(self):
        with patch("app.services.captcha._random_answer", return_value="ABC234"):
            return self.client.get("/captcha")

    def test_captcha_is_raster_with_no_answer_in_json_cookie_or_database(self):
        response = self.captcha()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json), {"id", "image_url"})
        self.assertNotIn("ABC234", response.get_data(as_text=True))
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        with self.client.session_transaction() as session:
            self.assertNotIn("ABC234", json.dumps(dict(session)))
            self.assertEqual(set(session), {"_challenge_browser"})
        row = db.session.get(CaptchaChallenge, response.json["id"])
        self.assertNotEqual(row.answer_digest, "ABC234")
        self.assertEqual(len(row.answer_digest), 64)
        image = self.client.get(response.json["image_url"])
        self.assertEqual(image.mimetype, "image/png")
        raster = Image.open(io.BytesIO(image.data))
        self.assertEqual(raster.size, (230, 78))
        self.assertEqual(raster.info, {})
        self.assertNotIn(b"ABC234", image.data)

    def test_captcha_wrong_answer_consumes_and_correct_answer_is_one_use(self):
        challenge = self.captcha().json
        payload = {"captcha_id": challenge["id"], "captcha_answer": "WRONG"}
        self.assertFalse(self.client.post("/verify-captcha", data=payload).json["valid"])
        payload["captcha_answer"] = "ABC234"
        self.assertFalse(self.client.post("/verify-captcha", data=payload).json["valid"])
        challenge = self.captcha().json
        payload = {"captcha_id": challenge["id"], "captcha_answer": " abc234 "}
        self.assertTrue(self.client.post("/verify-captcha", data=payload).json["valid"])
        self.assertFalse(self.client.post("/verify-captcha", data=payload).json["valid"])

    def test_captcha_browser_binding_and_expiration(self):
        challenge = self.captcha().json
        other = self.app.test_client()
        self.assertEqual(other.get(challenge["image_url"]).status_code, 404)
        payload = {"captcha_id": challenge["id"], "captcha_answer": "ABC234"}
        self.assertFalse(other.post("/verify-captcha", data=payload).json["valid"])
        row = db.session.get(CaptchaChallenge, challenge["id"])
        row.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.client.get(challenge["image_url"]).status_code, 404)
        self.assertFalse(self.client.post("/verify-captcha", data=payload).json["valid"])
        self.captcha()
        self.assertIsNone(db.session.get(CaptchaChallenge, challenge["id"]))

    def test_password_roundtrip_and_replay_rejection(self):
        payload = encrypted_password(self.client, "register", "MyPässword123!")
        response = self.client.post("/consume/register", data=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["digest"], hashlib.sha256("MyPässword123!".encode()).hexdigest())
        self.assertTrue(response.json["confirmation_matches"])
        self.assertEqual(self.client.post("/consume/register", data=payload).status_code, 400)
        self.assertEqual(PasswordChallenge.query.count(), 0)

    def test_plaintext_is_never_accepted_even_with_valid_envelope(self):
        self.assertEqual(self.client.post("/consume/login", data={"password": "Secret123"}).status_code, 400)
        payload = encrypted_password(self.client, "login", "Secret123")
        self.assertEqual(self.client.post("/consume/login", data={**payload, "password": ""}).status_code, 400)
        self.assertEqual(self.client.post("/consume/login", data={**payload, "confirm": ""}).status_code, 400)

    def test_envelope_binds_browser_purpose_and_nonce(self):
        payload = encrypted_password(self.client, "login", "Secret123")
        other = self.app.test_client()
        self.assertEqual(other.post("/consume/login", data=payload).status_code, 400)
        self.assertEqual(self.client.post("/consume/reset", data=payload).status_code, 400)
        self.assertEqual(self.client.post("/consume/login", data=payload).status_code, 200)
        challenge = self.client.get("/password-challenge?purpose=login").json
        wrong = encrypt_challenge(challenge, "Secret123", nonce="A" * 43)
        self.assertEqual(self.client.post("/consume/login", data=wrong).status_code, 400)
        correct = encrypt_challenge(challenge, "Secret123")
        self.assertEqual(self.client.post("/consume/login", data=correct).status_code, 400)

    def test_expired_password_challenge_and_invalid_purpose(self):
        self.assertEqual(self.client.get("/password-challenge?purpose=unknown").status_code, 400)
        response = self.client.get("/password-challenge?purpose=reset")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        payload = encrypt_challenge(response.json, "Secret123")
        row = db.session.get(PasswordChallenge, response.json["id"])
        row.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.client.post("/consume/reset", data=payload).status_code, 400)

    def test_utf8_size_limit_and_arbitrary_json_control_characters(self):
        for password in ("é" * 64, "\0" * 128):
            payload = encrypted_password(self.client, "reset", password)
            self.assertEqual(self.client.post("/consume/reset", data=payload).status_code, 200)
        for password in ("é" * 65, ""):
            payload = encrypted_password(self.client, "reset", password)
            self.assertEqual(self.client.post("/consume/reset", data=payload).status_code, 400)

    def test_wrong_padding_and_malformed_ciphertext_fail_closed(self):
        for wire in ("!!!", base64.b64encode(b"short").decode()):
            challenge = self.client.get("/password-challenge?purpose=login").json
            response = self.client.post("/consume/login", data={
                "password_challenge": challenge["id"], "password_envelope": wire,
            })
            self.assertEqual(response.status_code, 400)
            self.assertIsNone(db.session.get(PasswordChallenge, challenge["id"]))
        challenge = self.client.get("/password-challenge?purpose=login").json
        public_key = serialization.load_pem_public_key(challenge["public_key"].encode())
        wire = public_key.encrypt(b"bad protocol", padding.PKCS1v15())
        self.assertEqual(self.client.post("/consume/login", data={
            "password_challenge": challenge["id"], "password_envelope": base64.b64encode(wire).decode(),
        }).status_code, 400)

    def test_production_requires_private_key_and_owner_only_permissions(self):
        production = Flask("production-test")
        production.config["REQUIRE_RUNTIME_SECRETS"] = True
        with self.assertRaisesRegex(RuntimeError, "required in production"):
            init_password_transport(production)
        production.config["PASSWORD_TRANSPORT_PRIVATE_KEY_FILE"] = str(self.key_file)
        self.key_file.chmod(0o644)
        try:
            with self.assertRaisesRegex(RuntimeError, "owner-only permissions"):
                init_password_transport(production)
        finally:
            self.key_file.chmod(0o600)
        init_password_transport(production)
        self.assertEqual(production.extensions["password_transport_key"].private_numbers(), self.key.private_numbers())

    def test_refresh_and_password_challenges_are_rate_limited(self):
        app = self.make_app(RATELIMIT_ENABLED=True, CHALLENGE_RATE_LIMIT="2 per minute")
        with app.app_context():
            db.create_all()
            client = app.test_client()
            for endpoint in ("/captcha", "/password-challenge?purpose=login"):
                self.assertEqual(client.get(endpoint).status_code, 200)
                self.assertEqual(client.get(endpoint).status_code, 200)
                self.assertEqual(client.get(endpoint).status_code, 429)
            db.session.remove()
            db.drop_all()

    def test_concurrent_consumption_only_one_request_succeeds(self):
        database = Path(self.key_dir.name) / "concurrent.db"
        app = self.make_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{database}")
        with app.app_context():
            db.create_all()
            original = app.test_client()
            with patch("app.services.captcha._random_answer", return_value="ABC234"):
                captcha = original.get("/captcha").json
            envelope = encrypted_password(original, "login", "Secret123")
            cookie = original.get_cookie(app.config["SESSION_COOKIE_NAME"])
            clients = [app.test_client(), app.test_client()]
            for client in clients:
                client.set_cookie(cookie.key, cookie.value)
            engine = db.engine
            for table, endpoint, payload in (
                ("password_challenges", "/consume/login", envelope),
                ("captcha_challenges", "/verify-captcha",
                 {"captcha_id": captcha["id"], "captcha_answer": "ABC234"}),
            ):
                barrier = threading.Barrier(2)

                def synchronize_reads(connection, cursor, statement, parameters, context, executemany):
                    if statement.lstrip().upper().startswith("SELECT") and table in statement and "WHERE" in statement:
                        barrier.wait(timeout=10)

                event.listen(engine, "after_cursor_execute", synchronize_reads)
                try:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        responses = list(pool.map(lambda client: client.post(endpoint, data=payload), clients))
                finally:
                    event.remove(engine, "after_cursor_execute", synchronize_reads)
                if table == "password_challenges":
                    self.assertEqual(sorted(response.status_code for response in responses), [200, 400])
                else:
                    self.assertEqual(sorted(response.json["valid"] for response in responses), [False, True])
            db.session.remove()
            db.drop_all()

    def test_shared_key_and_database_allow_consumption_by_another_worker(self):
        database = Path(self.key_dir.name) / "workers.db"
        app_one = self.make_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{database}")
        app_two = self.make_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{database}")
        with app_one.app_context():
            db.create_all()
        client_one, client_two = app_one.test_client(), app_two.test_client()
        payload = encrypted_password(client_one, "bind_email", "Secret123")
        cookie = client_one.get_cookie(app_one.config["SESSION_COOKIE_NAME"])
        client_two.set_cookie(cookie.key, cookie.value)
        self.assertEqual(client_two.post("/consume/bind_email", data=payload).status_code, 200)
        self.assertEqual(client_one.post("/consume/bind_email", data=payload).status_code, 400)
        with app_one.app_context():
            db.session.remove()
            db.drop_all()

    @unittest.skipUnless(shutil.which("node"), "Node.js required for real vendored-browser interoperability")
    def test_vendored_forge_oaep_interoperates_with_python(self):
        challenge = self.client.get("/password-challenge?purpose=login").json
        bundle = Path(__file__).resolve().parents[1] / "static/vendor/forge.min.js"
        script = r"""
const fs = require('fs'), vm = require('vm'), crypto = require('crypto');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = {console, Uint8Array, setTimeout, clearTimeout, crypto: crypto.webcrypto};
context.window = context; context.self = context;
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const forge = context.forge, key = forge.pki.publicKeyFromPem(input.public_key);
const payload = JSON.stringify({nonce:input.nonce,password_b64:forge.util.encode64(forge.util.encodeUtf8('浏览器Password123!'))});
const seed = crypto.randomBytes(32).toString('binary');
process.stdout.write(forge.util.encode64(key.encrypt(payload, 'RSA-OAEP', {
  md:forge.md.sha256.create(),mgf1:{md:forge.md.sha256.create()},seed
})));
"""
        result = subprocess.run([shutil.which("node"), "-e", script, str(bundle)],
                                input=json.dumps(challenge), text=True, capture_output=True,
                                check=True, timeout=20)
        response = self.client.post("/consume/login", data={
            "password_challenge": challenge["id"], "password_envelope": result.stdout,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["digest"], hashlib.sha256("浏览器Password123!".encode()).hexdigest())

    @unittest.skipUnless(shutil.which("node"), "Node.js required to execute password form script")
    def test_password_form_script_confirmation_fetch_failure_and_ciphertext_only_submit(self):
        challenge = self.client.get("/password-challenge?purpose=register").json
        root = Path(__file__).resolve().parents[1]
        script = r"""
const fs = require('fs'), vm = require('vm'), crypto = require('crypto'), assert = require('assert');
const challenge = JSON.parse(fs.readFileSync(0,'utf8'));
const listeners = {}, children = [], requests = [];
function input(name, value='') {
 return {name,value,attrs:{},setAttribute(k,v){this.attrs[k]=v;},removeAttribute(k){if(k==='name')this.name='';}};
}
const password=input('password','BrowserPassword123!'), confirm=input('confirm','mismatch');
let submitted=null, failure=true;
const form={dataset:{passwordPurpose:'register'},
 querySelector(s){
  if(s==='[data-password-field]')return password;
  if(s==='[data-password-confirm]')return confirm;
  if(s==='[data-password-error]')return children.find(c=>'data-password-error' in c.attrs);
  const m=s.match(/^input\[name="([^"]+)"\]$/); return m?children.find(c=>c.name===m[1]):null;
 },
 appendChild(c){children.push(c);},addEventListener(n,f){listeners[n]=f;}
};
function NativeForm(){}
NativeForm.prototype.submit=function(){submitted=Object.fromEntries(children.filter(c=>c.name).map(c=>[c.name,c.value]));};
const context={Uint8Array,setTimeout,clearTimeout,crypto:crypto.webcrypto,HTMLFormElement:NativeForm,
 document:{readyState:'complete',querySelectorAll(s){return s==='form[data-password-purpose]'?[form]:[];},createElement(){return input('');}},
 async fetch(url,options){requests.push({url,options});return {ok:!failure,json:async()=>challenge};}
};
context.window=context;context.self=context;
vm.runInNewContext(fs.readFileSync(process.argv[1]+'/static/vendor/forge.min.js','utf8'),context);
vm.runInNewContext(fs.readFileSync(process.argv[1]+'/static/js/passwords.js','utf8'),context);
const submitter={disabled:false}, event={submitter,preventDefault(){}};
(async()=>{
 assert.equal(password.name,'');assert.equal(confirm.name,'');
 await listeners.submit(event);
 assert.equal(requests.length,0);assert.equal(submitted,null);
 assert.match(form.querySelector('[data-password-error]').textContent,/不一致/);
 confirm.value=password.value;
 await listeners.submit(event);
 assert.equal(requests.length,1);assert.equal(submitted,null);assert.equal(submitter.disabled,false);
 assert.equal(password.value,'BrowserPassword123!');
 failure=false;
 await listeners.submit(event);
 assert.equal(requests.length,2);assert.equal(requests[1].options.credentials,'same-origin');
 assert.equal(requests[1].options.cache,'no-store');assert.equal(requests[1].options.body,undefined);
 assert.equal(password.value,'');assert.equal(confirm.value,'');
 assert.deepEqual(Object.keys(submitted).sort(),['password_challenge','password_envelope']);
 process.stdout.write(JSON.stringify(submitted));
})().catch(error=>{console.error(error);process.exit(1);});
"""
        result = subprocess.run([shutil.which("node"), "-e", script, str(root)],
                                input=json.dumps(challenge), text=True, capture_output=True,
                                check=True, timeout=20)
        response = self.client.post("/consume/register", data=json.loads(result.stdout))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["digest"], hashlib.sha256(b"BrowserPassword123!").hexdigest())

    @unittest.skipUnless(shutil.which("node"), "Node.js required to execute email form script")
    def test_email_script_sends_only_proof_fields_and_recovers_after_fetch_error(self):
        root = Path(__file__).resolve().parents[1]
        script = r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert');
function field(value=''){return {value,disabled:false,textContent:'',handlers:{},addEventListener(n,f){this.handlers[n]=f;},reportValidity(){return true;},focus(){this.focused=true;}};}
const fields={email:field('ui-proof@pku.edu.cn'),username:field('ui-proof'),csrf_token:field('csrf-proof'),
 captcha_id:field('captcha-proof'),captcha_answer:field('ABC234'),email_code:field(''),email_challenge:field('')};
const button=field(),status=field(),requests=[];let refreshes=0,tick=null,failure=false;
const refresh={click(){refreshes++;}};
const form={dataset:{emailPurpose:'register'},querySelector(selector){
 const special={'[data-send-email-code]':button,'[data-email-status]':status,'[data-captcha-refresh]':refresh};
 if(special[selector])return special[selector];
 const m=selector.match(/^\[name=(?:"([^"]+)"|([^\]]+))\]$/);return m?fields[m[1]||m[2]]:null;
}};
const context={URLSearchParams,document:{querySelectorAll(){return [form];}},
 fetch:async(url,options)=>{requests.push({url,options});if(failure)throw new Error('network offline');return {ok:true,json:async()=>({id:'email-proof',message:'sent',resend_after:1})};},
 setInterval(fn){tick=fn;return 1;},clearInterval(){},};context.window=context;
vm.runInNewContext(fs.readFileSync(process.argv[1]+'/static/js/email_verification.js','utf8'),context);
(async()=>{
 await button.handlers.click();
 assert.equal(requests.length,1);assert.equal(requests[0].url,'/email-code');
 assert.deepEqual([...requests[0].options.body.keys()].sort(),['captcha_answer','captcha_id','csrf_token','email','purpose','username']);
 assert.equal(fields.email_challenge.value,'email-proof');assert.equal(refreshes,1);assert.equal(button.disabled,true);
 await button.handlers.click();assert.equal(requests.length,1);
 tick();assert.equal(button.disabled,false);
 fields.email_code.value='123456';fields.email.handlers.input();
 assert.equal(fields.email_challenge.value,'');assert.equal(fields.email_code.value,'');
 failure=true;await button.handlers.click();
 assert.equal(button.disabled,false);assert.equal(refreshes,2);assert.match(status.textContent,/无法发送/);
 fields.captcha_answer.value='';await button.handlers.click();
 assert.equal(requests.length,2);assert.equal(fields.captcha_answer.focused,true);
 process.stdout.write('email script passed');
})().catch(error=>{console.error(error);process.exit(1);});
"""
        result = subprocess.run([shutil.which("node"), "-e", script, str(root)],
                                text=True, capture_output=True, check=True, timeout=20)
        self.assertEqual(result.stdout, "email script passed")


if __name__ == "__main__":
    unittest.main()
