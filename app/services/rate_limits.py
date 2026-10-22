from flask import g
from flask_limiter.util import get_remote_address


def user_rate_key() -> str:
    """Share a user's limit across IPs; trust only the configured proxy layer."""
    user = getattr(g, "current_user", None)
    if user is not None:
        return f"user:{user.auth_id}"
    return f"ip:{get_remote_address()}"
