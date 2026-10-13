from database.connection import get_db


NOTE_SELECT = """SELECT n.*, u.username AS author_username, u.full_name AS author_name
                 FROM investigation_notes n LEFT JOIN users u ON n.analyst_id = u.user_id"""


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS investigation_notes (
        note_id INTEGER PRIMARY KEY,
        incident_id INTEGER NOT NULL REFERENCES incidents(incident_id),
        analyst_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
        note_content TEXT NOT NULL CHECK (length(trim(note_content)) > 0),
        creation_timestamp TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_incident ON investigation_notes(incident_id)")


def get_notes(incident_id):
    rows = get_db().execute(NOTE_SELECT + " WHERE n.incident_id = ? ORDER BY n.note_id", (incident_id,)).fetchall()
    return [dict(row) for row in rows]
