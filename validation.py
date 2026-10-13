"""Validate JSON before it reaches the database."""

import re

from database.roles import ROLES
from errors import ApiError


def text(data, field, maximum, minimum=1):
    value = data.get(field)
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ApiError(f"{field} must contain {minimum} to {maximum} characters")
    value = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ApiError(f"{field} contains invalid characters")
    return value


def fields(data, allowed, required):
    if not isinstance(data, dict):
        raise ApiError("Request body must be a JSON object")
    unknown = set(data) - set(allowed)
    missing = set(required) - set(data)
    if unknown:
        raise ApiError("Unknown fields", details=sorted(unknown))
    if missing:
        raise ApiError("Missing required fields", details=sorted(missing))


def email(data):
    value = text(data, "email", 254).lower()
    if not re.fullmatch(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}", value):
        raise ApiError("Email format is invalid")
    local, domain = value.split("@")
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise ApiError("Email format is invalid")
    for label in domain.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ApiError("Email format is invalid")
    return value


def password(data):
    value = data.get("password")
    if not isinstance(value, str) or not 8 <= len(value) <= 128:
        raise ApiError("Password must contain 8 to 128 characters")
    if not (re.search(r"[A-Z]", value) and re.search(r"[a-z]", value)
            and re.search(r"[0-9]", value) and re.search(r"[^\w\s]", value)):
        raise ApiError("Password must include uppercase, lowercase, a digit, and a symbol")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ApiError("Password contains invalid characters")
    return value


def registration(data):
    required = ("full_name", "username", "email", "password", "department", "role")
    fields(data, required, required)
    username = text(data, "username", 50, 3).lower()
    if not re.fullmatch(r"[a-z0-9_.-]+", username):
        raise ApiError("Username may contain only letters, digits, dots, underscores, and hyphens")
    role = text(data, "role", 30)
    if role not in ROLES:
        raise ApiError("Invalid role", details=list(ROLES))
    return {
        "full_name": text(data, "full_name", 120), "username": username,
        "email": email(data), "password": password(data),
        "department": text(data, "department", 100), "role": role,
    }

