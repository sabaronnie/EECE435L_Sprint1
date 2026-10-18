from database.connection import get_db, utc_now


VULNERABILITY_SELECT = """SELECT v.*, a.asset_name AS affected_asset_name
                          FROM vulnerabilities v LEFT JOIN assets a ON v.affected_asset_id = a.asset_id"""


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
        vulnerability_id INTEGER PRIMARY KEY,
        title TEXT NOT NULL CHECK (length(trim(title)) > 0),
        description TEXT NOT NULL,
        cve_identifier TEXT,
        cvss_score REAL NOT NULL CHECK (cvss_score BETWEEN 0 AND 10),
        severity_level TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
        affected_asset_id INTEGER NOT NULL REFERENCES assets(asset_id),
        discovery_source TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open'
            CHECK (status IN ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')),
        creation_date TEXT NOT NULL,
        resolution_date TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset ON vulnerabilities(affected_asset_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity_level)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status)")


def get_vulnerability_by_id(vulnerability_id):
    row = get_db().execute(
        VULNERABILITY_SELECT + " WHERE v.vulnerability_id = ?", (vulnerability_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def get_vulnerabilities():
    rows = get_db().execute(VULNERABILITY_SELECT + " ORDER BY v.vulnerability_id").fetchall()
    return [dict(row) for row in rows]


def search_vulnerabilities(filters):
    columns = {
        "cve_identifier": "v.cve_identifier", "severity_level": "v.severity_level",
        "affected_asset_id": "v.affected_asset_id", "asset_name": "a.asset_name",
        "status": "v.status",
    }
    conditions = []
    values = []
    for field, value in filters.items():
        column = columns[field]
        if field in ("cve_identifier", "asset_name"):
            conditions.append(f"instr(lower({column}), lower(?)) > 0")
        else:
            conditions.append(f"{column} = ?")
        values.append(value)
    query = VULNERABILITY_SELECT + " WHERE " + " AND ".join(conditions) + " ORDER BY v.vulnerability_id"
    return [dict(row) for row in get_db().execute(query, values).fetchall()]


def insert_vulnerability(data):
    cursor = get_db().execute(
        """INSERT INTO vulnerabilities (title, description, cve_identifier, cvss_score, severity_level,
           affected_asset_id, discovery_source, creation_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (data["title"], data["description"], data["cve_identifier"], data["cvss_score"],
         data["severity_level"], data["affected_asset_id"], data["discovery_source"], utc_now()),
    )
    return get_vulnerability_by_id(cursor.lastrowid)


def update_vulnerability(vulnerability_id, updates):
    assignments = ", ".join(f"{field} = ?" for field in updates)
    get_db().execute(
        f"UPDATE vulnerabilities SET {assignments} WHERE vulnerability_id = ?",
        (*updates.values(), vulnerability_id),
    )
    return get_vulnerability_by_id(vulnerability_id)


def delete_vulnerability(vulnerability_id):
    return get_db().execute(
        "DELETE FROM vulnerabilities WHERE vulnerability_id = ?", (vulnerability_id,),
    ).rowcount
