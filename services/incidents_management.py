"""Incident management logic. HTTP routes are defined in app.py."""

from auth import ANALYST, REGULAR
from database import assets, get_db, incidents, investigation_notes
from database.logs import record_activity
from database.users import UserRepository
from errors import ApiError
import validation


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
    record_activity(actor, "INCIDENT_ASSIGNED", f"Assigned incident {incident_id} to analyst {analyst['user_id']}",
                    related_service="Incident Management")
    return incident
