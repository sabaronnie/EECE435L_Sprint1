"""Notification and alert logic. HTTP routes are defined in app.py."""

from auth import ANALYST, check_notification_owner
from database import notifications
from database.logs import record_activity
from database.users import UserRepository
from errors import ApiError
import validation


def notify(user_id, title, message, notification_type, severity):
    """Queue a notification inside the caller's transaction; the caller's activity record commits it."""
    return notifications.insert_notification({
        "user_id": user_id, "title": title, "message": message,
        "notification_type": notification_type, "severity_level": severity,
    })


def notify_role(role, title, message, notification_type, severity):
    return [notify(user["user_id"], title, message, notification_type, severity)
            for user in UserRepository().active_by_role(role)]


def find_notification(notification_id):
    notification = notifications.get_notification_by_id(notification_id)
    if notification is None:
        raise ApiError("Notification not found", 404)
    return notification


def create_notification(data, actor):
    data = validation.notification_creation(data)
    if UserRepository().by_id(data["user_id"]) is None:
        raise ApiError("Notification recipient does not exist")
    notification = notifications.insert_notification(data)
    record_activity(actor, "NOTIFICATION_CREATED",
                    f"Sent {notification['notification_type']} notification {notification['notification_id']} "
                    f"to user {notification['user_id']}",
                    related_service="Notification and Alert Management")
    return notification


def user_notifications(user_id):
    if UserRepository().by_id(user_id) is None:
        raise ApiError("User not found", 404)
    return notifications.get_notifications_by_user(user_id)


def get_notification(notification_id):
    return find_notification(notification_id)


def search_notifications(filters, actor):
    filters = validation.notification_search(filters)
    if actor["role"] == ANALYST:
        check_notification_owner(filters.get("user_id", actor["user_id"]), actor)
        filters["user_id"] = actor["user_id"]
    return notifications.search_notifications(filters)


def mark_read(notification_id, actor):
    notification = find_notification(notification_id)
    if notification["status"] == "Read":
        return notification
    notification = notifications.mark_read(notification_id)
    record_activity(actor, "NOTIFICATION_READ", f"Marked notification {notification_id} as read",
                    related_service="Notification and Alert Management")
    return notification


def delete_notification(notification_id, actor):
    find_notification(notification_id)
    if not notifications.delete_notification(notification_id):
        raise ApiError("Notification not found", 404)
    record_activity(actor, "NOTIFICATION_DELETED", f"Deleted notification {notification_id}",
                    "Warning", "Notification and Alert Management")
