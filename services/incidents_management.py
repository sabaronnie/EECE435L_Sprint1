"""Incident management logic. HTTP routes are defined in app.py."""

from auth import ADMIN, ANALYST, REGULAR, check_incident_access
from database import assets, get_db, incidents, investigation_notes
from database.connection import utc_now
from database.logs import record_activity
from database.users import UserRepository
from errors import ApiError
from services.notifications_management import notify, notify_role
import validation

NEXT_STATUS = {
    "Open": "Under Investigation",
    "Under Investigation": "Mitigated",
    "Mitigated": "Resolved",
    "Resolved": "Closed",
}


def find_incident(incident_id):
    incident = incidents.get_incident_by_id(incident_id)
    if incident is None:
        raise ApiError("Incident not found", 404)
    return incident


def lock_incident(incident_id):
    # Assignment and workflow changes must see a consistent incident record.
    get_db().execute("BEGIN IMMEDIATE")
    return find_incident(incident_id)


def get_incident(incident_id):
    incident = find_incident(incident_id)
    incident["investigation_notes"] = investigation_notes.get_notes(incident_id)
    return incident


def list_incidents():
    return incidents.get_incidents()


def create_incident(data, actor):
    data = validation.incident_creation(data)
    if actor["role"] == REGULAR and data["reporter_id"] != actor["user_id"]:
        raise ApiError("You may only report incidents as yourself", 403)
    if UserRepository().by_id(data["reporter_id"]) is None:
        raise ApiError("Incident reporter does not exist")
    if assets.get_asset_by_id(data["asset_id"]) is None:
        raise ApiError("Affected asset does not exist")
    incident = incidents.insert_incident(data)
    if incident["severity"] in ("High", "Critical"):
        notify_role(ADMIN, f"{incident['severity']} incident reported",
                    f"Incident {incident['incident_id']} ({incident['title']}) needs an assigned analyst",
                    "Security Alert", incident["severity"])
    record_activity(actor, "INCIDENT_CREATED", f"Created incident {incident['incident_id']}: {incident['title']}",
                    related_service="Incident Management")
    incident["investigation_notes"] = []
    return incident


def assign_incident(incident_id, data, actor):
    data = validation.incident_assignment(data)
    lock_incident(incident_id)
    analyst = UserRepository().by_id(data["analyst_id"])
    if analyst is None:
        raise ApiError("Assigned analyst does not exist")
    if analyst["role"] != ANALYST:
        raise ApiError("Assigned user must have the Security Analyst role")
    if analyst["account_status"] != "Active":
        raise ApiError("Assigned analyst must have an active account")
    incident = incidents.assign_incident(incident_id, analyst["user_id"])
    notify(analyst["user_id"], "New incident assigned",
           f"You were assigned incident {incident_id}: {incident['title']}",
           "Incident Assignment", incident["severity"])
    record_activity(actor, "INCIDENT_ASSIGNED", f"Assigned incident {incident_id} to analyst {analyst['user_id']}",
                    related_service="Incident Management")
    return incident


def update_status(incident_id, data, actor):
    data = validation.incident_status(data)
    incident = lock_incident(incident_id)
    check_incident_access(incident, actor)
    next_status = NEXT_STATUS.get(incident["status"])
    if next_status is None:
        raise ApiError("Closed incidents cannot change status", 409)
    if data["status"] != next_status:
        raise ApiError(f"Incident must move from {incident['status']} to {next_status}", 409)
    resolution_date = utc_now() if next_status == "Resolved" else incident["resolution_date"]
    updated = incidents.update_status(incident_id, next_status, resolution_date)
    record_activity(actor, "INCIDENT_STATUS_CHANGED", f"Changed incident {incident_id} from {incident['status']} to {next_status}",
                    related_service="Incident Management")
    return updated


def add_note(incident_id, data, actor):
    data = validation.investigation_note(data)
    incident = lock_incident(incident_id)
    check_incident_access(incident, actor)
    note = investigation_notes.insert_note(incident_id, actor["user_id"], data["note_content"])
    record_activity(actor, "INVESTIGATION_NOTE_ADDED", f"Added note {note['note_id']} to incident {incident_id}",
                    related_service="Incident Management")
    return note
