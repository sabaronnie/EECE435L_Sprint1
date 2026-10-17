"""System audit schema and activity writes. Logs cannot be edited."""

from database.connection import get_db, utc_now


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        log_id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
        actor_user_id INTEGER,
        actor_username TEXT,
        action_performed TEXT NOT NULL,
        description TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        severity_level TEXT NOT NULL
            CHECK (severity_level IN ('Information', 'Warning', 'Error', 'Critical')),
        related_service TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity_level)")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(logs)").fetchall()}
    conn.execute("DROP TRIGGER IF EXISTS prevent_log_changes")
    if "actor_user_id" not in columns:
        conn.execute("ALTER TABLE logs ADD COLUMN actor_user_id INTEGER")
        conn.execute("UPDATE logs SET actor_user_id = user_id WHERE actor_user_id IS NULL")
    # The account foreign key may clear user_id on account deletion; actor_user_id preserves the original ID.
    conn.execute("""CREATE TRIGGER prevent_log_changes
        BEFORE UPDATE ON logs WHEN
            NOT (OLD.user_id IS NOT NULL AND NEW.user_id IS NULL
                 AND NOT EXISTS (SELECT 1 FROM users WHERE user_id = OLD.user_id))
            OR NEW.log_id IS NOT OLD.log_id
            OR NEW.actor_user_id IS NOT OLD.actor_user_id
            OR NEW.actor_username IS NOT OLD.actor_username
            OR NEW.action_performed IS NOT OLD.action_performed
            OR NEW.description IS NOT OLD.description
            OR NEW.timestamp IS NOT OLD.timestamp
            OR NEW.severity_level IS NOT OLD.severity_level
            OR NEW.related_service IS NOT OLD.related_service
        BEGIN SELECT RAISE(ABORT, 'Audit records cannot be changed'); END""")


def record_activity(actor, action, description, severity="Information", related_service="Users and Identity Management"):
    actor_user_id = actor["actor_user_id"] if actor and "actor_user_id" in actor.keys() else None
    user_id = actor["user_id"] if actor else None
    cursor = get_db().execute(
        """INSERT INTO logs
           (user_id, actor_user_id, actor_username, action_performed, description, timestamp,
            severity_level, related_service) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, actor_user_id if actor_user_id is not None else user_id,
         actor["username"] if actor else None,
         action, description, utc_now(), severity, related_service),
    )
    get_db().commit()
    return get_log_by_id(cursor.lastrowid)


def get_log_by_id(log_id):
    row = get_db().execute("SELECT * FROM logs WHERE log_id = ?", (log_id,)).fetchone()
    return _log_dict(row) if row is not None else None


def get_logs():
    rows = get_db().execute("SELECT * FROM logs ORDER BY log_id").fetchall()
    return [_log_dict(row) for row in rows]


def get_logs_by_user(user_id):
    rows = get_db().execute(
        "SELECT * FROM logs WHERE COALESCE(user_id, actor_user_id) = ? ORDER BY log_id", (user_id,),
    ).fetchall()
    return [_log_dict(row) for row in rows]


def search_logs(filters):
    columns = {
        "user_id": "COALESCE(user_id, actor_user_id)", "date": "timestamp", "action": "action_performed",
        "severity": "severity_level", "related_service": "related_service",
    }
    conditions = []
    values = []
    for field, value in filters.items():
        column = columns[field]
        if field == "date":
            conditions.append(f"substr({column}, 1, 10) = ?")
        elif field in ("action", "related_service"):
            conditions.append(f"instr(lower({column}), lower(?)) > 0")
        else:
            conditions.append(f"{column} = ?")
        values.append(value)
    query = "SELECT * FROM logs WHERE " + " AND ".join(conditions) + " ORDER BY log_id"
    return [_log_dict(row) for row in get_db().execute(query, values).fetchall()]


def _log_dict(row):
    result = dict(row)
    if result.get("actor_user_id") is not None:
        result["user_id"] = result["actor_user_id"]
    return result


def delete_log(log_id):
    return get_db().execute("DELETE FROM logs WHERE log_id = ?", (log_id,)).rowcount
