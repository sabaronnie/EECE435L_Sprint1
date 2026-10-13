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
