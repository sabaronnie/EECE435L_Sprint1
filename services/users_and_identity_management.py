"""Service 1: Users and Identity Management."""

from datetime import datetime, timedelta, timezone
import secrets
import sqlite3

import click
from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from auth import ADMIN, AUDITOR, REGULAR, require_auth, require_owner_or_admin, require_roles, token_hash
from database import get_db
from database.connection import utc_now
from database.logs import record_activity
from database.roles import ROLES
from database.users import UserRepository, public_user
from errors import ApiError
import validation

users_api = Blueprint("users", __name__, url_prefix="/api/RonnieSaba/users")


class IdentityService:
    def __init__(self):
        self.users = UserRepository()

    def register(self, data, actor=None):
        password_hash = generate_password_hash(data["password"], method="scrypt")
        user = self.users.insert(data, password_hash)
        record_activity(actor or user, "USER_REGISTERED", f"Created user {user['user_id']}")
        return public_user(user)

    def login(self, identifier, password):
        user = self.users.by_identifier(identifier)
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
        return {"token": token, "token_type": "Bearer", "expires_at": expires,
                "user": public_user(self.users.by_id(user["user_id"]))}

    def update(self, user_id, data, actor):
        if self.users.by_id(user_id) is None:
            raise ApiError("User not found", 404)
        get_db().execute(
            "UPDATE users SET full_name = ?, email = ?, department_id = ? WHERE user_id = ?",
            (data["full_name"], data["email"], self.users.department_id(data["department"]), user_id),
        )
        record_activity(actor, "USER_UPDATED", f"Updated user {user_id}")
        return public_user(self.users.by_id(user_id))

    def lock_user(self, user_id):
        # Keep concurrent admin changes from removing the last active admin.
        get_db().execute("BEGIN IMMEDIATE")
        user = self.users.by_id(user_id)
        if user is None:
            raise ApiError("User not found", 404)
        return user

    def protect_last_admin(self, user):
        if user["role"] == ADMIN and user["account_status"] == "Active":
            count = get_db().execute(
                """SELECT COUNT(*) FROM users u JOIN roles r USING (role_id)
                   WHERE r.name = ? AND u.account_status = 'Active'""", (ADMIN,),
            ).fetchone()[0]
            if count <= 1:
                raise ApiError("The last active administrator must be kept", 409)

    def delete(self, user_id, actor):
        user = self.lock_user(user_id)
        self.protect_last_admin(user)
        get_db().execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        if actor["user_id"] == user_id:
            actor = {**dict(actor), "user_id": None}
        record_activity(actor, "USER_DELETED", f"Deleted user {user_id}")

    def change_role(self, user_id, role, actor):
        user = self.lock_user(user_id)
        if role != ADMIN:
            self.protect_last_admin(user)
        get_db().execute("UPDATE users SET role_id = ? WHERE user_id = ?", (self.users.role_id(role), user_id))
        get_db().execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        record_activity(actor, "USER_ROLE_CHANGED", f"Changed role for user {user_id} to {role}")
        return public_user(self.users.by_id(user_id))


@users_api.post("/register")
def register():
    data = validation.registration(request.get_json())
    if g.actor is not None:
        require_roles(ADMIN, REGULAR)
    if data["role"] != REGULAR:
        require_roles(ADMIN)
    user = IdentityService().register(data, g.actor)
    return jsonify(status="success", message="User registered successfully", user=user), 201


@users_api.post("/login")
def login():
    data = request.get_json()
    validation.fields(data, ("identifier", "password"), ("identifier", "password"))
    identifier = validation.text(data, "identifier", 254).lower()
    password = data["password"]
    if not isinstance(password, str) or not 1 <= len(password) <= 128:
        raise ApiError("Password must be a non-empty string of at most 128 characters")
    return jsonify(status="success", message="Authentication successful",
                   **IdentityService().login(identifier, password))


@users_api.get("")
@require_auth
def list_users():
    require_roles(ADMIN, AUDITOR)
    users = [public_user(user) for user in UserRepository().all()]
    return jsonify(status="success", users=users)


@users_api.get("/<username>")
@require_auth
def get_user(username):
    require_roles(ADMIN, AUDITOR, REGULAR)
    if g.actor["role"] == REGULAR and username.lower() != g.actor["username"].lower():
        raise ApiError("You may only view your own profile", 403)
    user = UserRepository().by_username(username)
    if user is None:
        raise ApiError("User not found", 404)
    return jsonify(status="success", user=public_user(user))


@users_api.put("/<int:user_id>")
@require_auth
def update_user(user_id):
    require_owner_or_admin(user_id)
    data = validation.profile(request.get_json())
    user = IdentityService().update(user_id, data, g.actor)
    return jsonify(status="success", message="User updated successfully", user=user)


@users_api.delete("/<int:user_id>")
@require_auth
def delete_user(user_id):
    require_roles(ADMIN)
    IdentityService().delete(user_id, g.actor)
    return jsonify(status="success", message="User deleted successfully")


@users_api.put("/<int:user_id>/role")
@require_auth
def change_role(user_id):
    require_roles(ADMIN)
    data = request.get_json()
    validation.fields(data, ("role",), ("role",))
    role = validation.text(data, "role", 30)
    if role not in ROLES:
        raise ApiError("Invalid role", details=list(ROLES))
    user = IdentityService().change_role(user_id, role, g.actor)
    return jsonify(status="success", message="User role updated successfully", user=user)


def register_commands(app):
    @app.cli.command("create-admin")
    @click.option("--full-name", prompt=True)
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--department", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin(full_name, username, email, department, password):
        """Create the first administrator through a trusted local command."""
        try:
            data = validation.registration(dict(full_name=full_name, username=username, email=email,
                                                department=department, password=password, role=ADMIN))
            user = IdentityService().register(data)
        except (ApiError, sqlite3.IntegrityError) as error:
            get_db().rollback()
            message = error.message if isinstance(error, ApiError) else "Username or email already exists"
            raise click.ClickException(message) from error
        click.echo(f"Administrator {user['username']} created.")
