def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS assets (
        asset_id INTEGER PRIMARY KEY,
        asset_name TEXT NOT NULL CHECK (length(trim(asset_name)) > 0),
        asset_type TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        operating_system TEXT,
        owner_id INTEGER NOT NULL REFERENCES users(user_id),
        department_id INTEGER NOT NULL REFERENCES departments(department_id),
        location TEXT,
        criticality_level TEXT NOT NULL CHECK (criticality_level IN ('Low', 'Medium', 'High', 'Critical')),
        status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'Under Maintenance'))
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner_id)")
