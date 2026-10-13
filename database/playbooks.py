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
