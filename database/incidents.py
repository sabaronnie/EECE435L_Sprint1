from database.connection import get_db, utc_now


INCIDENT_SELECT = """SELECT i.*, reporter.username AS reporter_username,
                            reporter.full_name AS reporter_name, a.asset_name,
                            analyst.username AS assigned_analyst_username,
                            analyst.full_name AS assigned_analyst_name
                     FROM incidents i JOIN users reporter ON i.reporter_id = reporter.user_id
                     LEFT JOIN assets a ON i.asset_id = a.asset_id
                     LEFT JOIN users analyst ON i.assigned_analyst_id = analyst.user_id"""


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS incidents (
        incident_id INTEGER PRIMARY KEY,
        title TEXT NOT NULL CHECK (length(trim(title)) > 0),
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
        reporter_id INTEGER NOT NULL REFERENCES users(user_id),
        asset_id INTEGER REFERENCES assets(asset_id),
        assigned_analyst_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'Open'
            CHECK (status IN ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')),
        creation_date TEXT NOT NULL,
        resolution_date TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_reporter ON incidents(reporter_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_asset ON incidents(asset_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_analyst ON incidents(assigned_analyst_id)")


def get_incident_by_id(incident_id):
    row = get_db().execute(INCIDENT_SELECT + " WHERE i.incident_id = ?", (incident_id,)).fetchone()
    return dict(row) if row is not None else None


def get_incidents():
    return [dict(row) for row in get_db().execute(INCIDENT_SELECT + " ORDER BY i.incident_id").fetchall()]


def insert_incident(data):
    cursor = get_db().execute(
        """INSERT INTO incidents (title, description, category, severity, reporter_id, asset_id, creation_date)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (data["title"], data["description"], data["category"], data["severity"],
         data["reporter_id"], data["asset_id"], utc_now()),
    )
    return get_incident_by_id(cursor.lastrowid)
