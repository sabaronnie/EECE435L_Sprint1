"""System audit schema and identity event writes. Logs cannot be edited."""

from database.connection import get_db, utc_now


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        log_id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
        actor_username TEXT,
        action_performed TEXT NOT NULL,
        description TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        severity_level TEXT NOT NULL
            CHECK (severity_level IN ('Information', 'Warning', 'Error', 'Critical')),
        related_service TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user_id)")
    # Allow only foreign-key cleanup when a user is deleted; retain the actor snapshot.
    conn.execute("""CREATE TRIGGER IF NOT EXISTS prevent_log_changes
        BEFORE UPDATE ON logs WHEN
            NOT (OLD.user_id IS NOT NULL AND NEW.user_id IS NULL
                 AND NOT EXISTS (SELECT 1 FROM users WHERE user_id = OLD.user_id))
            OR NEW.log_id IS NOT OLD.log_id
            OR NEW.actor_username IS NOT OLD.actor_username
            OR NEW.action_performed IS NOT OLD.action_performed
            OR NEW.description IS NOT OLD.description
            OR NEW.timestamp IS NOT OLD.timestamp
            OR NEW.severity_level IS NOT OLD.severity_level
            OR NEW.related_service IS NOT OLD.related_service
        BEGIN SELECT RAISE(ABORT, 'Audit records cannot be changed'); END""")


def record_activity(actor, action, description, severity="Information"):
    get_db().execute(
        """INSERT INTO logs
           (user_id, actor_username, action_performed, description, timestamp,
            severity_level, related_service) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (actor["user_id"] if actor else None, actor["username"] if actor else None,
         action, description, utc_now(), severity, "Users and Identity Management"),
    )
    get_db().commit()
