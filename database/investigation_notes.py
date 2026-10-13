def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS investigation_notes (
        note_id INTEGER PRIMARY KEY,
        incident_id INTEGER NOT NULL REFERENCES incidents(incident_id),
        analyst_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
        note_content TEXT NOT NULL CHECK (length(trim(note_content)) > 0),
        creation_timestamp TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_incident ON investigation_notes(incident_id)")
