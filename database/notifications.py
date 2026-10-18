from database.connection import get_db, utc_now


NOTIFICATION_SELECT = """SELECT n.*, u.username AS username, u.full_name AS user_full_name
                         FROM notifications n JOIN users u ON n.user_id = u.user_id"""


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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status)")


def get_notification_by_id(notification_id):
    row = get_db().execute(
        NOTIFICATION_SELECT + " WHERE n.notification_id = ?", (notification_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def get_notifications_by_user(user_id):
    rows = get_db().execute(
        NOTIFICATION_SELECT + " WHERE n.user_id = ? ORDER BY n.creation_date DESC, n.notification_id DESC",
        (user_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def search_notifications(filters):
    columns = {
        "user_id": "n.user_id", "notification_type": "n.notification_type",
        "severity_level": "n.severity_level", "status": "n.status",
    }
    conditions = [f"{columns[field]} = ?" for field in filters]
    query = NOTIFICATION_SELECT + " WHERE " + " AND ".join(conditions) + " ORDER BY n.notification_id"
    return [dict(row) for row in get_db().execute(query, list(filters.values())).fetchall()]


def insert_notification(data):
    cursor = get_db().execute(
        """INSERT INTO notifications (user_id, title, message, notification_type, severity_level, creation_date)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (data["user_id"], data["title"], data["message"], data["notification_type"],
         data["severity_level"], utc_now()),
    )
    return get_notification_by_id(cursor.lastrowid)


def mark_read(notification_id):
    get_db().execute(
        "UPDATE notifications SET status = 'Read', read_date = ? WHERE notification_id = ? AND status = 'Unread'",
        (utc_now(), notification_id),
    )
    return get_notification_by_id(notification_id)


def delete_notification(notification_id):
    return get_db().execute(
        "DELETE FROM notifications WHERE notification_id = ?", (notification_id,),
    ).rowcount
