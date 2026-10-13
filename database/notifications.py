def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS notifications (
        notification_id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        title TEXT NOT NULL CHECK (length(trim(title)) > 0),
        message TEXT NOT NULL,
        notification_type TEXT NOT NULL CHECK (notification_type IN (
            'Incident Assignment', 'Security Alert', 'System Notification', 'Threat Alert', 'Vulnerability Alert'
        )),
        severity_level TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
        status TEXT NOT NULL DEFAULT 'Unread' CHECK (status IN ('Unread', 'Read')),
        creation_date TEXT NOT NULL,
        read_date TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)")
