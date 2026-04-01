from flask import Blueprint, redirect, render_template, request, session, url_for

from ..content import DEFAULT_THEME, THEME_OPTION_MAP, build_promo_slides


public_bp = Blueprint("public", __name__)


@public_bp.route("/")
def index():
    return render_template("index.html", promo_slides=build_promo_slides())


@public_bp.route("/theme", methods=["POST"])
def set_theme():
    theme_name = request.form.get("theme", DEFAULT_THEME)
    if theme_name in THEME_OPTION_MAP:
        session["theme_name"] = theme_name
    else:
        session.pop("theme_name", None)

    target = request.form.get("next") or request.referrer or url_for("public.index")
    return redirect(target)
