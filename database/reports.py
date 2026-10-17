"""Read-only aggregate queries used by the security reports service."""

from database.connection import get_db


def count_rows(table):
    # Callers use only fixed table names defined by the application.
    return get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def grouped_count(table, column):
    rows = get_db().execute(
        f"SELECT {column}, COUNT(*) AS count FROM {table} GROUP BY {column} ORDER BY {column}"
    ).fetchall()
    return {row[0]: row[1] for row in rows}


def active_incident_count():
    return get_db().execute(
        "SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved', 'Closed')"
    ).fetchone()[0]


def critical_threat_count():
    return get_db().execute(
        "SELECT COUNT(*) FROM threats WHERE severity_level = 'Critical'"
    ).fetchone()[0]


def critical_asset_count():
    return get_db().execute(
        "SELECT COUNT(*) FROM assets WHERE criticality_level = 'Critical'"
    ).fetchone()[0]


def critical_vulnerability_count():
    return get_db().execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE severity_level = 'Critical'"
    ).fetchone()[0]


def recent_threats(limit=5):
    rows = get_db().execute(
        "SELECT * FROM threats ORDER BY date_added DESC, threat_id DESC LIMIT ?", (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def recent_activities(limit=5):
    rows = get_db().execute(
        """SELECT log_id, COALESCE(user_id, actor_user_id) AS user_id, actor_username,
                  action_performed, description, timestamp, severity_level, related_service
           FROM logs ORDER BY timestamp DESC, log_id DESC LIMIT ?""", (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def activity_totals():
    row = get_db().execute(
        """SELECT COUNT(*) AS total_activity_records,
                  SUM(CASE WHEN COALESCE(user_id, actor_user_id) IS NOT NULL THEN 1 ELSE 0 END)
                      AS total_user_activities,
                  SUM(CASE WHEN action_performed IN ('LOGIN_SUCCESS', 'LOGIN_FAILED') THEN 1 ELSE 0 END)
                      AS login_attempts,
                  SUM(CASE WHEN action_performed = 'LOGIN_FAILED' THEN 1 ELSE 0 END)
                      AS failed_login_attempts
           FROM logs"""
    ).fetchone()
    return {key: row[key] or 0 for key in row.keys()}


def most_performed_actions(limit=10):
    rows = get_db().execute(
        """SELECT action_performed AS action, COUNT(*) AS count FROM logs
           GROUP BY action_performed ORDER BY count DESC, action_performed LIMIT ?""", (limit,),
    ).fetchall()
    return [dict(row) for row in rows]
