"""Raster CAPTCHA with server-side answers and atomic, one-attempt consumption."""

import hashlib
import hmac
import io
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app, session, url_for
from PIL import Image, ImageDraw, ImageFilter, ImageFont

from ..extensions import db
from ..models_challenges import CaptchaChallenge


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def browser_hash(*, create=False):
    token = session.get("_challenge_browser")
    if not token and create:
        token = secrets.token_urlsafe(32)
        session["_challenge_browser"] = token
    if not isinstance(token, str):
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _random_answer():
    return "".join(secrets.choice("23456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(6))


def _answer_digest(challenge_id, answer):
    secret = current_app.config["SECRET_KEY"]
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    message = f"captcha:v1:{challenge_id}:{answer}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _render_png(answer):
    """Render pixels only: no SVG text, metadata, or encoded answer in URLs."""
    random = secrets.SystemRandom()
    image = Image.new("RGB", (230, 78), (248, 246, 240))
    draw = ImageDraw.Draw(image)
    for _ in range(240):
        x, y = random.randrange(230), random.randrange(78)
        draw.ellipse((x, y, x + 1, y + 1), fill=(155, 162, 169))
    try:
        font = ImageFont.truetype(current_app.config.get("CAPTCHA_FONT_PATH") or "DejaVuSans.ttf", 38)
    except OSError:
        font = ImageFont.load_default()
    for index, letter in enumerate(answer):
        glyph = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        glyph_draw = ImageDraw.Draw(glyph)
        bbox = glyph_draw.textbbox((0, 0), letter, font=font)
        height = bbox[3] - bbox[1]
        glyph_draw.text((12, 6 - bbox[1]), letter, font=font,
                        fill=(random.randrange(25, 85), random.randrange(25, 85), random.randrange(25, 85), 255))
        if height < 24:
            glyph = glyph.crop(glyph.getbbox()).resize((25, 38), Image.Resampling.LANCZOS)
        glyph = glyph.rotate(random.randrange(-20, 21), Image.Resampling.BICUBIC, expand=True)
        image.paste(glyph, (index * 35 + 5, random.randrange(8, 17)), glyph)
    draw = ImageDraw.Draw(image)
    for _ in range(4):
        draw.line([(0, random.randrange(78)), (115, random.randrange(78)),
                   (230, random.randrange(78))], fill=(125, 135, 145), width=1)
    image = image.filter(ImageFilter.SMOOTH)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def create_captcha():
    now = utcnow()
    # Bound routine cleanup so an anonymous request cannot trigger a large scan.
    expired = db.select(CaptchaChallenge.id).where(CaptchaChallenge.expires_at <= now).limit(100)
    db.session.execute(db.delete(CaptchaChallenge).where(CaptchaChallenge.id.in_(expired)))
    challenge_id = secrets.token_urlsafe(32)
    answer = _random_answer()
    row = CaptchaChallenge(
        id=challenge_id, browser_hash=browser_hash(create=True),
        answer_digest=_answer_digest(challenge_id, answer), image_png=_render_png(answer),
        expires_at=now + timedelta(seconds=current_app.config.get("CAPTCHA_TTL_SECONDS", 300)),
    )
    db.session.add(row)
    db.session.commit()
    return {"id": challenge_id, "image_url": url_for("challenges.captcha_image", challenge_id=challenge_id)}


def captcha_image_bytes(challenge_id):
    if not isinstance(challenge_id, str) or len(challenge_id) != 43:
        return None
    row = db.session.execute(db.select(CaptchaChallenge).where(
        CaptchaChallenge.id == challenge_id,
        CaptchaChallenge.browser_hash == browser_hash(),
        CaptchaChallenge.expires_at > utcnow(),
    )).scalar_one_or_none()
    return row.image_png if row else None


def verify_captcha(challenge_id, answer):
    """Consume one matching browser's attempt, including incorrect answers.

    Call before adding business mutations: this function commits consumption so
    later failed registration validation cannot make the challenge reusable.
    """
    if not isinstance(challenge_id, str) or len(challenge_id) != 43 or not browser_hash():
        return False
    row = db.session.execute(db.select(CaptchaChallenge).where(
        CaptchaChallenge.id == challenge_id,
        CaptchaChallenge.browser_hash == browser_hash(),
        CaptchaChallenge.expires_at > utcnow(),
    )).scalar_one_or_none()
    if row is None:
        return False
    expected = row.answer_digest
    deleted = db.session.execute(db.delete(CaptchaChallenge).where(
        CaptchaChallenge.id == challenge_id,
        CaptchaChallenge.browser_hash == browser_hash(),
        CaptchaChallenge.expires_at > utcnow(),
    ), execution_options={"synchronize_session": False}).rowcount
    db.session.commit()
    if deleted != 1 or not isinstance(answer, str) or len(answer) > 32:
        return False
    supplied = _answer_digest(challenge_id, answer.strip().upper())
    return hmac.compare_digest(expected, supplied)
