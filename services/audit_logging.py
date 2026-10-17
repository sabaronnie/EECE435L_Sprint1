"""Audit log service logic. HTTP routes are defined in app.py."""

from database import logs as audit_logs
from database.users import UserRepository
from database.logs import record_activity
from errors import ApiError
import validation


def find_log(log_id):
    log = audit_logs.get_log_by_id(log_id)
    if log is None:
        raise ApiError("Audit log not found", 404)
    return log


def list_logs():
    return audit_logs.get_logs()


def get_log(log_id):
    return find_log(log_id)


def search_logs(filters):
    return audit_logs.search_logs(validation.audit_log_search(filters))


def logs_for_user(user_id):
    return audit_logs.get_logs_by_user(user_id)


def create_log(data):
    data = validation.audit_log_creation(data)
    actor = UserRepository().by_id(data["user_id"])
    if actor is None:
        raise ApiError("User not found", 404)
    return record_activity(actor, data["action_performed"], data["description"],
                           data["severity_level"], data["related_service"])


def delete_log(log_id, actor):
    log = find_log(log_id)
    audit_logs.delete_log(log_id)
    record_activity(actor, "AUDIT_LOG_DELETED", f"Deleted audit log {log_id}",
                    "Warning", "Security Audit Logging")
    return log
