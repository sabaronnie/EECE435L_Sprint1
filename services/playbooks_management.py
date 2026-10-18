"""Security playbook and response action logic. HTTP routes are defined in app.py."""

from auth import ADMIN, ANALYST
from database import get_db, playbooks, response_actions
from database.connection import utc_now
from database.logs import record_activity
from database.users import UserRepository
from errors import ApiError
from services.notifications_management import notify
import validation

NEXT_STATUS = {"Pending": "In Progress", "In Progress": "Completed"}


def find_playbook(playbook_id):
    playbook = playbooks.get_playbook_by_id(playbook_id)
    if playbook is None:
        raise ApiError("Playbook not found", 404)
    return playbook


def find_action(action_id):
    action = response_actions.get_action_by_id(action_id)
    if action is None:
        raise ApiError("Response action not found", 404)
    return action


def check_assignee(user_id):
    user = UserRepository().by_id(user_id)
    if user is None:
        raise ApiError("Assigned user does not exist")
    if user["role"] not in (ADMIN, ANALYST):
        raise ApiError("Response actions can only be assigned to security administrators or analysts")
    if user["account_status"] != "Active":
        raise ApiError("Assigned user must have an active account")


def notify_assignee(user_id, action, playbook, actor):
    if user_id is not None and user_id != actor["user_id"]:
        notify(user_id, "Response action assigned",
               f"Step {action['step_number']} of playbook {playbook['playbook_name']}: {action['action_description']}",
               "System Notification", playbook["severity_level"])


def lock_playbook(playbook_id):
    # Step numbers and deletions must see a consistent set of actions.
    get_db().execute("BEGIN IMMEDIATE")
    return find_playbook(playbook_id)


def list_playbooks():
    return playbooks.get_playbooks()


def get_playbook(playbook_id):
    playbook = find_playbook(playbook_id)
    playbook["response_actions"] = response_actions.get_actions(playbook_id)
    return playbook


def create_playbook(data, actor):
    data = validation.playbook_creation(data)
    playbook = playbooks.insert_playbook(data, actor["user_id"])
    record_activity(actor, "PLAYBOOK_CREATED",
                    f"Created playbook {playbook['playbook_id']}: {playbook['playbook_name']}",
                    related_service="Security Playbook and Response Automation")
    playbook["response_actions"] = []
    return playbook


def delete_playbook(playbook_id, actor):
    playbook = lock_playbook(playbook_id)
    in_progress = [action["step_number"] for action in response_actions.get_actions(playbook_id)
                   if action["status"] == "In Progress"]
    if in_progress:
        raise ApiError("Playbook has response actions in progress and cannot be deleted", 409,
                       details={"in_progress_steps": in_progress})
    if not playbooks.delete_playbook(playbook_id):
        raise ApiError("Playbook not found", 404)
    record_activity(actor, "PLAYBOOK_DELETED",
                    f"Deleted playbook {playbook_id}: {playbook['playbook_name']} "
                    f"with {playbook['action_count']} response actions",
                    "Warning", "Security Playbook and Response Automation")


def add_action(playbook_id, data, actor):
    data = validation.response_action_creation(data)
    playbook = lock_playbook(playbook_id)
    if any(action["step_number"] == data["step_number"] for action in response_actions.get_actions(playbook_id)):
        raise ApiError(f"Playbook already has a response action for step {data['step_number']}", 409)
    if data["assigned_user_id"] is not None:
        check_assignee(data["assigned_user_id"])
    action = response_actions.insert_action(playbook_id, data)
    notify_assignee(action["assigned_user_id"], action, playbook, actor)
    record_activity(actor, "RESPONSE_ACTION_ADDED",
                    f"Added action {action['action_id']} as step {action['step_number']} of playbook {playbook_id}",
                    related_service="Security Playbook and Response Automation")
    return action


def update_action_status(action_id, data, actor):
    updates = validation.response_action_update(data)
    get_db().execute("BEGIN IMMEDIATE")
    action = find_action(action_id)
    playbook = find_playbook(action["playbook_id"])
    current_status = action["status"]
    if current_status == "Completed":
        raise ApiError("Completed response actions cannot be changed", 409)
    new_status = updates.get("status", current_status)
    if new_status != current_status:
        if new_status != NEXT_STATUS[current_status]:
            raise ApiError(f"Response action must move from {current_status} to {NEXT_STATUS[current_status]}", 409)
        earlier = response_actions.unfinished_earlier_steps(action["playbook_id"], action["step_number"])
        if earlier:
            raise ApiError("Earlier response steps must be completed first", 409, details={"unfinished_steps": earlier})
    if updates.get("assigned_user_id") is not None:
        check_assignee(updates["assigned_user_id"])
    assignee = updates.get("assigned_user_id", action["assigned_user_id"])
    if new_status != "Pending" and assignee is None:
        # Work that has started is always tracked against the user performing it.
        updates["assigned_user_id"] = assignee = actor["user_id"]
    if "completion_date" in updates:
        if new_status != "Completed":
            raise ApiError("Completion date can only be set when the action is completed", 409)
    elif new_status == "Completed":
        updates["completion_date"] = utc_now()
    updated = response_actions.update_action(action_id, updates)
    if assignee != action["assigned_user_id"]:
        notify_assignee(assignee, updated, playbook, actor)
    description = f"Updated action {action_id} (step {action['step_number']} of playbook {action['playbook_id']})"
    if new_status != current_status:
        description += f" from {current_status} to {new_status}"
    if assignee != action["assigned_user_id"]:
        description += f"; assigned to user {assignee}"
    record_activity(actor, "RESPONSE_ACTION_UPDATED", description,
                    related_service="Security Playbook and Response Automation")
    return updated
