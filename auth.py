"""Expiring bearer sessions and role/ownership checks."""

from functools import wraps
from hashlib import sha256

from flask import g, request

from database import get_db
from database.connection import utc_now
from database.users import UserRepository
from errors import ApiError

ADMIN = "SECURITY_ADMINISTRATOR"
REGULAR = "REGULAR_USER"
AUDITOR = "AUDITOR"


def token_hash(token):
    return sha256(token.encode("utf-8")).hexdigest()


def authenticate():
    g.actor = None
    g.session_id = None
    header = request.headers.get("Authorization")
    if header is None:
        return
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or len(parts[1]) > 256:
        raise ApiError("Use Authorization: Bearer <token>", 401)
    session = get_db().execute(
        "SELECT * FROM auth_sessions WHERE token_hash = ? AND expires_at > ?",
        (token_hash(parts[1]), utc_now()),
    ).fetchone()
    actor = UserRepository().by_id(session["user_id"]) if session else None
    if actor is None or actor["account_status"] != "Active":
        raise ApiError("Invalid or expired authentication token", 401)
    g.actor = actor
    g.session_id = session["session_id"]


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.actor is None:
            raise ApiError("Authentication is required", 401)
        return view(*args, **kwargs)
    return wrapped


def require_roles(*roles):
    if g.actor is None:
        raise ApiError("Authentication is required", 401)
    if g.actor["role"] not in roles:
        raise ApiError("User does not have permission to perform this operation", 403)


def require_owner_or_admin(user_id):
    require_roles(ADMIN, REGULAR)
    if g.actor["role"] != ADMIN and g.actor["user_id"] != user_id:
        raise ApiError("You may only update your own profile", 403)
