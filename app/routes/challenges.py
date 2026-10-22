from flask import Blueprint, Response, abort, current_app, jsonify, request

from ..extensions import limiter
from ..services.captcha import captcha_image_bytes, create_captcha
from ..services.password_transport import PasswordTransportError, create_password_challenge


challenges_bp = Blueprint("challenges", __name__)


@challenges_bp.after_request
def prevent_challenge_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@challenges_bp.get("/captcha")
@limiter.limit(lambda: current_app.config.get("CHALLENGE_RATE_LIMIT", "20 per minute"))
def captcha():
    return jsonify(create_captcha())


@challenges_bp.get("/captcha/<challenge_id>.png")
@limiter.limit(lambda: current_app.config.get("CHALLENGE_IMAGE_RATE_LIMIT", "60 per minute"))
def captcha_image(challenge_id):
    content = captcha_image_bytes(challenge_id)
    if content is None:
        abort(404)
    response = Response(content, mimetype="image/png")
    response.headers["Cache-Control"] = "no-store"
    return response


@challenges_bp.get("/password-challenge")
@limiter.limit(lambda: current_app.config.get("CHALLENGE_RATE_LIMIT", "20 per minute"))
def password_challenge():
    try:
        return jsonify(create_password_challenge(request.args.get("purpose", "")))
    except PasswordTransportError:
        abort(400)
