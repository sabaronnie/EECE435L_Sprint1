"""Incident management logic. HTTP routes are defined in app.py."""

from auth import REGULAR
from database import assets, incidents
from database.logs import record_activity
from database.users import UserRepository
from errors import ApiError
import validation


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
