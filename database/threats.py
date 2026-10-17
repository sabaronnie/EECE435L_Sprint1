from database.connection import get_db, utc_now


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS threats (
        threat_id INTEGER PRIMARY KEY,
        threat_type TEXT NOT NULL CHECK (threat_type IN (
            'IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other Indicators'
        )),
        threat_value TEXT NOT NULL CHECK (length(trim(threat_value)) > 0),
        description TEXT NOT NULL,
        severity_level TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
        source TEXT NOT NULL,
        date_added TEXT NOT NULL,
        UNIQUE (threat_type, threat_value)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity_level)")


def get_threat_by_id(threat_id):
    row = get_db().execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
    return dict(row) if row is not None else None


def get_threats():
    rows = get_db().execute("SELECT * FROM threats ORDER BY threat_id").fetchall()
    return [dict(row) for row in rows]


def search_threats(filters):
    columns = {
        "threat_type": "threat_type", "threat_value": "threat_value",
        "severity_level": "severity_level", "source": "source",
    }
    conditions = []
    values = []
    for field, value in filters.items():
        column = columns[field]
        if field in ("threat_value", "source"):
            conditions.append(f"instr(lower({column}), lower(?)) > 0")
        else:
            conditions.append(f"{column} = ?")
        values.append(value)
    query = "SELECT * FROM threats WHERE " + " AND ".join(conditions) + " ORDER BY threat_id"
    return [dict(row) for row in get_db().execute(query, values).fetchall()]


def insert_threat(data):
    cursor = get_db().execute(
        """INSERT INTO threats (threat_type, threat_value, description, severity_level, source, date_added)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (data["threat_type"], data["threat_value"], data["description"],
         data["severity_level"], data["source"], utc_now()),
    )
    return get_threat_by_id(cursor.lastrowid)


def update_threat(threat_id, updates):
    assignments = ", ".join(f"{field} = ?" for field in updates)
    get_db().execute(
        f"UPDATE threats SET {assignments} WHERE threat_id = ?",
        (*updates.values(), threat_id),
    )
    return get_threat_by_id(threat_id)


def delete_threat(threat_id):
    return get_db().execute("DELETE FROM threats WHERE threat_id = ?", (threat_id,)).rowcount
