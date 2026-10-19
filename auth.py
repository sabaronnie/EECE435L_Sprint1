"""Expiring bearer sessions and role/ownership checks."""

from functools import wraps
from hashlib import sha256

from flask import g, request

from database import get_db
from database.connection import utc_now
from database.incidents import get_incident_by_id
from database.notifications import get_notification_by_id
from database.users import UserRepository
from errors import ApiError

ADMIN = "SECURITY_ADMINISTRATOR"
ANALYST = "SECURITY_ANALYST"
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


def require_roles(*roles):
    if getattr(g, "actor", None) is None:
        raise ApiError("Authentication is required", 401)
    if roles and g.actor["role"] not in roles:
        raise ApiError("User does not have permission to perform this operation", 403)


def roles_required(*roles):
    """Authenticate the caller, then check the roles allowed by the endpoint."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            authenticate()
            require_roles(*roles)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def login_required(view):
    """Allow any active user with a valid login token."""
    return roles_required()(view)


def admin_required(view):
    """Allow only an authenticated security administrator."""
    return roles_required(ADMIN)(view)


def registration_allowed(view):
    """Allow public signup; optionally identify any caller for privileged roles."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        authenticate()
        return view(*args, **kwargs)
    return wrapped


def own_profile_required(view):
    """After a role wrapper, restrict regular users to their own profile."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        require_roles(ADMIN, AUDITOR, REGULAR)
        if g.actor["role"] == REGULAR:
            user_id = kwargs.get("user_id")
            username = kwargs.get("username")
            if user_id is not None and user_id != g.actor["user_id"]:
                raise ApiError("You may only update your own profile", 403)
            if username is not None and username.lower() != g.actor["username"].lower():
                raise ApiError("You may only view your own profile", 403)
        return view(*args, **kwargs)
    return wrapped


def check_incident_access(incident, actor):
    if actor is None:
        raise ApiError("Authentication is required", 401)
    if actor["role"] == REGULAR and incident["reporter_id"] != actor["user_id"]:
        raise ApiError("You may only view incidents you reported", 403)
    if actor["role"] == ANALYST and incident["assigned_analyst_id"] != actor["user_id"]:
        raise ApiError("You may only access incidents assigned to you", 403)


def incident_access_required(view):
    """After a role wrapper, restrict access to reported or assigned incidents."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        require_roles(ADMIN, ANALYST, AUDITOR, REGULAR)
        incident = get_incident_by_id(kwargs["incident_id"])
        if incident is None:
            raise ApiError("Incident not found", 404)
        check_incident_access(incident, g.actor)
        return view(*args, **kwargs)
    return wrapped


def check_notification_owner(user_id, actor):
    if actor is None:
        raise ApiError("Authentication is required", 401)
    if actor["role"] in (ANALYST, REGULAR) and user_id != actor["user_id"]:
        raise ApiError("You may only access your own notifications", 403)


def own_notifications_required(view):
    """After a role wrapper, restrict analysts and regular users to their own notification list."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        require_roles(ADMIN, ANALYST, AUDITOR, REGULAR)
        check_notification_owner(kwargs["user_id"], g.actor)
        return view(*args, **kwargs)
    return wrapped


def notification_access_required(view):
    """After a role wrapper, restrict analysts and regular users to notifications they received."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        require_roles(ADMIN, ANALYST, AUDITOR, REGULAR)
        notification = get_notification_by_id(kwargs["notification_id"])
        if notification is None:
            raise ApiError("Notification not found", 404)
        check_notification_owner(notification["user_id"], g.actor)
        return view(*args, **kwargs)
    return wrapped
