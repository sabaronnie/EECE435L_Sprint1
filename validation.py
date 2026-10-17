"""Validate JSON before it reaches the database."""

from ipaddress import ip_address
import re

from database.roles import ROLES
from errors import ApiError

ASSET_TYPES = ("Server", "Workstation", "Database", "Application", "Network Device", "Cloud Resource")
CRITICALITY_LEVELS = ("Low", "Medium", "High", "Critical")
ASSET_STATUSES = ("Active", "Inactive", "Under Maintenance")
INCIDENT_SEVERITIES = ("Low", "Medium", "High", "Critical")
INCIDENT_STATUSES = ("Open", "Under Investigation", "Mitigated", "Resolved", "Closed")
THREAT_TYPES = ("IP Address", "Domain", "File Hash", "Malware Signature", "Other Indicators")
THREAT_SEVERITIES = ("Low", "Medium", "High", "Critical")


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


def profile(data):
    required = ("full_name", "email", "department")
    fields(data, required, required)
    return {
        "full_name": text(data, "full_name", 120),
        "email": email(data),
        "department": text(data, "department", 100),
    }


def choice(data, field, allowed):
    value = text(data, field, 50)
    if value not in allowed:
        raise ApiError(f"Invalid {field}", details=list(allowed))
    return value


def positive_id(data, field):
    value = data.get(field)
    if type(value) is not int or value <= 0:
        raise ApiError(f"{field} must be a positive integer")
    return value


def owner_id(data):
    return positive_id(data, "owner_id")


def asset_ip(data):
    value = text(data, "ip_address", 45)
    try:
        # Scoped IPv6 addresses depend on a local interface and are not asset addresses.
        if "%" in value:
            raise ValueError
        return str(ip_address(value))
    except ValueError:
        raise ApiError("IP address format is invalid") from None


def optional_text(data, field, maximum):
    if data.get(field) is None:
        return None
    return text(data, field, maximum)


def asset_creation(data):
    required = ("asset_name", "asset_type", "ip_address", "department", "owner_id", "criticality_level")
    fields(data, (*required, "operating_system", "location", "status"), required)
    return {
        "asset_name": text(data, "asset_name", 120),
        "asset_type": choice(data, "asset_type", ASSET_TYPES),
        "ip_address": asset_ip(data),
        "department": text(data, "department", 100),
        "owner_id": owner_id(data),
        "criticality_level": choice(data, "criticality_level", CRITICALITY_LEVELS),
        "status": choice(data, "status", ASSET_STATUSES) if "status" in data else "Active",
        "operating_system": optional_text(data, "operating_system", 120),
        "location": optional_text(data, "location", 200),
    }


def asset_update(data):
    required = ("asset_name", "owner_id", "department", "criticality_level", "status")
    fields(data, required, required)
    return {
        "asset_name": text(data, "asset_name", 120),
        "owner_id": owner_id(data),
        "department": text(data, "department", 100),
        "criticality_level": choice(data, "criticality_level", CRITICALITY_LEVELS),
        "status": choice(data, "status", ASSET_STATUSES),
    }


def asset_search(data):
    allowed = ("asset_name", "asset_type", "ip_address", "department", "criticality_level")
    fields(data, allowed, ())
    if not data:
        raise ApiError("Provide at least one asset search field")
    result = {}
    for field in data:
        if field == "asset_type":
            result[field] = choice(data, field, ASSET_TYPES)
        elif field == "criticality_level":
            result[field] = choice(data, field, CRITICALITY_LEVELS)
        elif field == "ip_address":
            result[field] = asset_ip(data)
        else:
            result[field] = text(data, field, 120 if field == "asset_name" else 100)
    return result


def incident_creation(data):
    required = ("title", "description", "category", "severity", "reporter_id", "asset_id")
    fields(data, required, required)
    return {
        "title": text(data, "title", 200),
        "description": text(data, "description", 8000),
        "category": text(data, "category", 100),
        "severity": choice(data, "severity", INCIDENT_SEVERITIES),
        "reporter_id": positive_id(data, "reporter_id"),
        "asset_id": positive_id(data, "asset_id"),
    }


def incident_assignment(data):
    fields(data, ("analyst_id",), ("analyst_id",))
    return {"analyst_id": positive_id(data, "analyst_id")}


def incident_status(data):
    fields(data, ("status",), ("status",))
    return {"status": choice(data, "status", INCIDENT_STATUSES)}


def investigation_note(data):
    fields(data, ("note_content",), ("note_content",))
    return {"note_content": text(data, "note_content", 8000)}


def threat_indicator(data):
    required = ("threat_type", "threat_value", "description", "severity", "source")
    fields(data, required, required)
    threat_type = choice(data, "threat_type", THREAT_TYPES)
    value = text(data, "threat_value", 512)
    if threat_type == "IP Address":
        try:
            if "%" in value:
                raise ValueError
            value = str(ip_address(value))
        except ValueError:
            raise ApiError("Threat value must be a valid IP address") from None
    elif threat_type == "Domain":
        value = value.rstrip(".").lower()
        labels = value.split(".")
        if (len(value) > 253 or len(labels) < 2
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise ApiError("Threat value must be a valid domain")
    elif threat_type == "File Hash":
        if not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})", value):
            raise ApiError("File hash must be a valid MD5, SHA-1, SHA-256, or SHA-512 hash")
        value = value.lower()
    return {
        "threat_type": threat_type,
        "threat_value": value,
        "description": text(data, "description", 4000),
        "severity_level": choice({"severity_level": data["severity"]}, "severity_level", THREAT_SEVERITIES),
        "source": text(data, "source", 200),
    }


def threat_update(data):
    fields(data, ("description", "severity", "source"), ())
    if not data:
        raise ApiError("Provide at least one threat field to update")
    result = {}
    if "description" in data:
        result["description"] = text(data, "description", 4000)
    if "severity" in data:
        result["severity_level"] = choice({"severity_level": data["severity"]}, "severity_level", THREAT_SEVERITIES)
    if "source" in data:
        result["source"] = text(data, "source", 200)
    return result


def threat_search(data):
    fields(data, ("threat_type", "threat_value", "severity", "source"), ())
    if not data:
        raise ApiError("Provide at least one threat search field")
    result = {}
    if "threat_type" in data:
        result["threat_type"] = choice(data, "threat_type", THREAT_TYPES)
    if "threat_value" in data:
        result["threat_value"] = text(data, "threat_value", 512)
    if "severity" in data:
        result["severity_level"] = choice({"severity_level": data["severity"]}, "severity_level", THREAT_SEVERITIES)
    if "source" in data:
        result["source"] = text(data, "source", 200)
    return result

