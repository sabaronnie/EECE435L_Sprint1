"""Threat intelligence service logic. HTTP routes are defined in app.py."""

from database import threats
from database.logs import record_activity
from errors import ApiError
import validation


def find_threat(threat_id):
    threat = threats.get_threat_by_id(threat_id)
    if threat is None:
        raise ApiError("Threat indicator not found", 404)
    return threat


def list_threats():
    return threats.get_threats()


def get_threat(threat_id):
    return find_threat(threat_id)


def search_threats(filters):
    return threats.search_threats(validation.threat_search(filters))


def create_threat(data, actor):
    data = validation.threat_indicator(data)
    threat = threats.insert_threat(data)
    record_activity(actor, "THREAT_CREATED", f"Added {threat['threat_type']} threat indicator {threat['threat_id']}",
                    related_service="Threat Intelligence")
    return threat


def update_threat(threat_id, data, actor):
    updates = validation.threat_update(data)
    find_threat(threat_id)
    threat = threats.update_threat(threat_id, updates)
    record_activity(actor, "THREAT_UPDATED", f"Updated threat indicator {threat_id}",
                    related_service="Threat Intelligence")
    return threat


def delete_threat(threat_id, actor):
    threat = find_threat(threat_id)
    if not threats.delete_threat(threat_id):
        raise ApiError("Threat indicator not found", 404)
    record_activity(actor, "THREAT_DELETED", f"Deleted threat indicator {threat_id}",
                    related_service="Threat Intelligence")
