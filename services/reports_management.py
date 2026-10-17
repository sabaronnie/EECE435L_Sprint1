"""Security report aggregation. HTTP routes are defined in app.py."""

from database import reports

SEVERITIES = ("Low", "Medium", "High", "Critical")
INCIDENT_STATUSES = ("Open", "Under Investigation", "Mitigated", "Resolved", "Closed")
VULNERABILITY_STATUSES = ("Open", "Under Investigation", "In Progress", "Resolved", "Closed")
THREAT_TYPES = ("IP Address", "Domain", "File Hash", "Malware Signature", "Other Indicators")


def _complete_counts(values, categories):
    return {category: values.get(category, 0) for category in categories}


def summary_report():
    return {
        "users": reports.count_rows("users"),
        "assets": reports.count_rows("assets"),
        "open_incidents": reports.active_incident_count(),
        "critical_threats": reports.critical_threat_count(),
        "recent_security_activities": reports.recent_activities(),
    }


def incident_report():
    return {
        "total_incidents": reports.count_rows("incidents"),
        "incidents_by_severity": _complete_counts(reports.grouped_count("incidents", "severity"), SEVERITIES),
        "incidents_by_status": _complete_counts(
            reports.grouped_count("incidents", "status"), INCIDENT_STATUSES,
        ),
    }


def asset_report():
    return {
        "total_assets": reports.count_rows("assets"),
        "critical_assets": reports.critical_asset_count(),
        "assets_by_type": reports.grouped_count("assets", "asset_type"),
    }


def threat_report():
    return {
        "total_threats": reports.count_rows("threats"),
        "threats_by_severity": _complete_counts(
            reports.grouped_count("threats", "severity_level"), SEVERITIES,
        ),
        "threats_by_type": _complete_counts(
            reports.grouped_count("threats", "threat_type"), THREAT_TYPES,
        ),
        "recent_threats": reports.recent_threats(),
    }


def vulnerability_report():
    return {
        "total_vulnerabilities": reports.count_rows("vulnerabilities"),
        "vulnerabilities_by_severity": _complete_counts(
            reports.grouped_count("vulnerabilities", "severity_level"), SEVERITIES,
        ),
        "vulnerabilities_by_status": _complete_counts(
            reports.grouped_count("vulnerabilities", "status"), VULNERABILITY_STATUSES,
        ),
        "critical_vulnerabilities": reports.critical_vulnerability_count(),
    }


def activity_report():
    return {
        **reports.activity_totals(),
        "most_performed_actions": reports.most_performed_actions(),
    }
