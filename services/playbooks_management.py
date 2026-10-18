"""Security playbook and response action logic. HTTP routes are defined in app.py."""

from database import get_db, playbooks, response_actions
from database.logs import record_activity
from errors import ApiError
import validation


def find_playbook(playbook_id):
    playbook = playbooks.get_playbook_by_id(playbook_id)
    if playbook is None:
        raise ApiError("Playbook not found", 404)
    return playbook


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
