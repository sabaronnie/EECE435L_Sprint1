"""Vulnerability management logic. HTTP routes are defined in app.py."""

from auth import ANALYST
from database import assets, get_db, vulnerabilities
from database.connection import utc_now
from database.logs import record_activity
from errors import ApiError
from services.notifications_management import notify, notify_role
import validation

NEXT_STATUS = {
    "Open": "Under Investigation",
    "Under Investigation": "In Progress",
    "In Progress": "Resolved",
    "Resolved": "Closed",
}
RESOLVED_STATUSES = ("Resolved", "Closed")


def cvss_severity(score):
    # CVSS v3.1 qualitative rating scale; a 0.0 score is stored as Low.
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def check_severity(score, severity):
    expected = cvss_severity(score)
    if severity != expected:
        raise ApiError(f"Severity level {severity} does not match CVSS score {score}; expected {expected}")


def find_vulnerability(vulnerability_id):
    vulnerability = vulnerabilities.get_vulnerability_by_id(vulnerability_id)
    if vulnerability is None:
        raise ApiError("Vulnerability not found", 404)
    return vulnerability


def lock_vulnerability(vulnerability_id):
    # Status changes must see a consistent vulnerability record.
    get_db().execute("BEGIN IMMEDIATE")
    return find_vulnerability(vulnerability_id)


def list_vulnerabilities():
    return vulnerabilities.get_vulnerabilities()


def get_vulnerability(vulnerability_id):
    return find_vulnerability(vulnerability_id)


def search_vulnerabilities(filters):
    return vulnerabilities.search_vulnerabilities(validation.vulnerability_search(filters))


def create_vulnerability(data, actor):
    data = validation.vulnerability_creation(data)
    check_severity(data["cvss_score"], data["severity_level"])
    asset = assets.get_asset_by_id(data["affected_asset_id"])
    if asset is None:
        raise ApiError("Affected asset does not exist")
    vulnerability = vulnerabilities.insert_vulnerability(data)
    if vulnerability["severity_level"] in ("High", "Critical"):
        title = f"{vulnerability['severity_level']} vulnerability on {asset['asset_name']}"
        message = (f"{vulnerability['cve_identifier']} (CVSS {vulnerability['cvss_score']}) was found on "
                   f"asset {asset['asset_id']}: {vulnerability['title']}")
        analysts = notify_role(ANALYST, title, message, "Vulnerability Alert", vulnerability["severity_level"])
        if asset["owner_id"] not in [notification["user_id"] for notification in analysts]:
            notify(asset["owner_id"], title, message, "Vulnerability Alert", vulnerability["severity_level"])
    record_activity(actor, "VULNERABILITY_CREATED",
                    f"Added vulnerability {vulnerability['vulnerability_id']} ({vulnerability['cve_identifier']}) "
                    f"on asset {vulnerability['affected_asset_id']}",
                    related_service="Vulnerability Management")
    return vulnerability


def update_vulnerability(vulnerability_id, data, actor):
    updates = validation.vulnerability_update(data)
    vulnerability = lock_vulnerability(vulnerability_id)
    current_status = vulnerability["status"]
    if current_status == "Closed":
        raise ApiError("Closed vulnerabilities cannot be changed", 409)
    new_status = updates.get("status", current_status)
    if new_status != current_status and new_status != NEXT_STATUS[current_status]:
        raise ApiError(f"Vulnerability must move from {current_status} to {NEXT_STATUS[current_status]}", 409)
    check_severity(updates.get("cvss_score", vulnerability["cvss_score"]),
                   updates.get("severity_level", vulnerability["severity_level"]))
    if "resolution_date" in updates:
        if new_status not in RESOLVED_STATUSES:
            raise ApiError("Resolution date can only be set on resolved or closed vulnerabilities", 409)
        if updates["resolution_date"][:10] < vulnerability["creation_date"][:10]:
            raise ApiError("Resolution date cannot be before the creation date")
    elif new_status == "Resolved" and current_status != "Resolved":
        updates["resolution_date"] = utc_now()
    updated = vulnerabilities.update_vulnerability(vulnerability_id, updates)
    description = f"Updated vulnerability {vulnerability_id}"
    if new_status != current_status:
        description += f" from {current_status} to {new_status}"
    record_activity(actor, "VULNERABILITY_UPDATED", description, related_service="Vulnerability Management")
    return updated


def delete_vulnerability(vulnerability_id, actor):
    vulnerability = find_vulnerability(vulnerability_id)
    if not vulnerabilities.delete_vulnerability(vulnerability_id):
        raise ApiError("Vulnerability not found", 404)
    record_activity(actor, "VULNERABILITY_DELETED",
                    f"Deleted vulnerability {vulnerability_id} ({vulnerability['cve_identifier']})",
                    "Warning", "Vulnerability Management")
