from database.connection import get_db, utc_now


PLAYBOOK_SELECT = """SELECT p.*, u.username AS created_by_username, u.full_name AS created_by_name,
                            (SELECT COUNT(*) FROM response_actions ra
                             WHERE ra.playbook_id = p.playbook_id) AS action_count,
                            (SELECT COUNT(*) FROM response_actions ra
                             WHERE ra.playbook_id = p.playbook_id AND ra.status = 'Completed') AS completed_actions
                     FROM playbooks p LEFT JOIN users u ON p.created_by = u.user_id"""


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS playbooks (
        playbook_id INTEGER PRIMARY KEY,
        playbook_name TEXT NOT NULL CHECK (length(trim(playbook_name)) > 0),
        description TEXT NOT NULL,
        incident_category TEXT NOT NULL,
        severity_level TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
        created_by INTEGER NOT NULL REFERENCES users(user_id),
        creation_date TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_playbooks_creator ON playbooks(created_by)")


def get_playbook_by_id(playbook_id):
    row = get_db().execute(PLAYBOOK_SELECT + " WHERE p.playbook_id = ?", (playbook_id,)).fetchone()
    return dict(row) if row is not None else None


def get_playbooks():
    rows = get_db().execute(PLAYBOOK_SELECT + " ORDER BY p.playbook_id").fetchall()
    return [dict(row) for row in rows]


def insert_playbook(data, created_by):
    cursor = get_db().execute(
        """INSERT INTO playbooks (playbook_name, description, incident_category, severity_level,
           created_by, creation_date) VALUES (?, ?, ?, ?, ?, ?)""",
        (data["playbook_name"], data["description"], data["incident_category"],
         data["severity_level"], created_by, utc_now()),
    )
    return get_playbook_by_id(cursor.lastrowid)


def delete_playbook(playbook_id):
    return get_db().execute("DELETE FROM playbooks WHERE playbook_id = ?", (playbook_id,)).rowcount
