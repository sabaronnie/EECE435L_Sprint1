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
