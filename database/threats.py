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
