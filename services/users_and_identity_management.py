"""Service 1: Users and Identity Management."""

from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash

from database.logs import record_activity
from database.users import UserRepository, public_user
from errors import ApiError
import validation

users_api = Blueprint("users", __name__, url_prefix="/api/RonnieSaba/users")


class IdentityService:
    def __init__(self):
        self.users = UserRepository()

    def register(self, data):
        password_hash = generate_password_hash(data["password"], method="scrypt")
        user = self.users.insert(data, password_hash)
        record_activity(user, "USER_REGISTERED", f"Created user {user['user_id']}")
        return public_user(user)


@users_api.post("/register")
def register():
    data = validation.registration(request.get_json())
    if data["role"] != "REGULAR_USER":
        raise ApiError("Administrator authentication is required to assign this role", 401)
    user = IdentityService().register(data)
    return jsonify(status="success", message="User registered successfully", user=user), 201
