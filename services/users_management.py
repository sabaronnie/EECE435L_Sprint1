"""User account logic. HTTP routes are defined in app.py."""

from datetime import datetime, timedelta, timezone
import secrets

from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

from auth import ADMIN, REGULAR, token_hash
from database import get_db
from database.connection import utc_now
from database.logs import record_activity
from database.roles import ROLES
from database.users import UserRepository, public_user
from errors import ApiError
import validation


def create_user(data, actor=None):
    """Shared by signup and the local administrator command."""
    password_hash = generate_password_hash(data["password"], method="scrypt")
    user = UserRepository().insert(data, password_hash)
    record_activity(actor or user, "USER_REGISTERED", f"Created user {user['user_id']}")
    return public_user(user)


def lock_user(user_id):
    # Keep concurrent admin changes from removing the last active admin.
    get_db().execute("BEGIN IMMEDIATE")
    user = UserRepository().by_id(user_id)
    if user is None:
        raise ApiError("User not found", 404)
    return user


def protect_last_admin(user):
    if user["role"] == ADMIN and user["account_status"] == "Active":
        count = get_db().execute(
            """SELECT COUNT(*) FROM users u JOIN roles r USING (role_id)
               WHERE r.name = ? AND u.account_status = 'Active'""", (ADMIN,),
        ).fetchone()[0]
        if count <= 1:
            raise ApiError("The last active administrator must be kept", 409)


def register_user(data, actor):
    data = validation.registration(data)
    if data["role"] != REGULAR:
        if actor is None:
            raise ApiError("Authentication is required", 401)
        if actor["role"] != ADMIN:
            raise ApiError("User does not have permission to perform this operation", 403)
    return create_user(data, actor)


def login_user(data):
    validation.fields(data, ("identifier", "password"), ("identifier", "password"))
    identifier = validation.text(data, "identifier", 254).lower()
    password = data["password"]
    if not isinstance(password, str) or not 1 <= len(password) <= 128:
        raise ApiError("Password must be a non-empty string of at most 128 characters")

    users = UserRepository()
    user = users.by_identifier(identifier)
    stored_hash = user["password_hash"] if user else current_app.config["DUMMY_PASSWORD_HASH"]
    matches = check_password_hash(stored_hash, password)
    if not user or not matches or user["account_status"] != "Active":
        record_activity(user, "LOGIN_FAILED", "Invalid credentials or inactive account", "Warning")
        raise ApiError("Invalid credentials or inactive account", 401)

    now = utc_now()
    expires = (datetime.now(timezone.utc) + timedelta(
        seconds=current_app.config["TOKEN_TTL_SECONDS"]
    )).isoformat(timespec="microseconds")
    token = secrets.token_urlsafe(32)
    db = get_db()
    db.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
    db.execute(
        "INSERT INTO auth_sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user["user_id"], token_hash(token), now, expires),
    )
    db.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?", (now, user["user_id"]))
    record_activity(user, "LOGIN_SUCCESS", "User logged in")
    return {
        "token": token, "token_type": "Bearer", "expires_at": expires,
        "user": public_user(users.by_id(user["user_id"])),
    }


def logout_user(session_id, actor):
    get_db().execute("DELETE FROM auth_sessions WHERE session_id = ?", (session_id,))
    record_activity(actor, "LOGOUT", "User logged out")


def list_users():
    return [public_user(user) for user in UserRepository().all()]


def get_user(username):
    user = UserRepository().by_username(username)
    if user is None:
        raise ApiError("User not found", 404)
    return public_user(user)


def update_user(user_id, data, actor):
    data = validation.profile(data)
    users = UserRepository()
    if users.by_id(user_id) is None:
        raise ApiError("User not found", 404)
    get_db().execute(
        "UPDATE users SET full_name = ?, email = ?, department_id = ? WHERE user_id = ?",
        (data["full_name"], data["email"], users.department_id(data["department"]), user_id),
    )
    record_activity(actor, "USER_UPDATED", f"Updated user {user_id}")
    return public_user(users.by_id(user_id))


def delete_user(user_id, actor):
    user = lock_user(user_id)
    protect_last_admin(user)
    get_db().execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    if actor["user_id"] == user_id:
        actor = {**dict(actor), "actor_user_id": actor["user_id"], "user_id": None}
    record_activity(actor, "USER_DELETED", f"Deleted user {user_id}")


def change_role(user_id, data, actor):
    validation.fields(data, ("role",), ("role",))
    role = validation.text(data, "role", 30)
    if role not in ROLES:
        raise ApiError("Invalid role", details=list(ROLES))
    user = lock_user(user_id)
    if role != ADMIN:
        protect_last_admin(user)
    users = UserRepository()
    get_db().execute("UPDATE users SET role_id = ? WHERE user_id = ?", (users.role_id(role), user_id))
    get_db().execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
    record_activity(actor, "USER_ROLE_CHANGED", f"Changed role for user {user_id} to {role}")
    return public_user(users.by_id(user_id))


def change_status(user_id, data, actor):
    validation.fields(data, ("account_status",), ("account_status",))
    status = validation.text(data, "account_status", 20)
    if status not in ("Active", "Inactive", "Suspended"):
        raise ApiError("Invalid account status")
    user = lock_user(user_id)
    if status != "Active":
        protect_last_admin(user)
    get_db().execute("UPDATE users SET account_status = ? WHERE user_id = ?", (status, user_id))
    get_db().execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
    record_activity(actor, "USER_STATUS_CHANGED", f"Changed status for user {user_id} to {status}")
    return public_user(UserRepository().by_id(user_id))


def create_admin(data):
    """Used by the trusted local command, never by a public route."""
    data = validation.registration({**data, "role": ADMIN})
    return create_user(data)
