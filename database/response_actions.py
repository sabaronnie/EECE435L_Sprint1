from database.connection import get_db


ACTION_SELECT = """SELECT ra.*, u.username AS assigned_username, u.full_name AS assigned_user_name
                   FROM response_actions ra LEFT JOIN users u ON ra.assigned_user_id = u.user_id"""


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS response_actions (
        action_id INTEGER PRIMARY KEY,
        playbook_id INTEGER NOT NULL REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
        action_description TEXT NOT NULL CHECK (length(trim(action_description)) > 0),
        step_number INTEGER NOT NULL CHECK (step_number > 0),
        status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'In Progress', 'Completed')),
        assigned_user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
        completion_date TEXT,
        UNIQUE (playbook_id, step_number)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_user ON response_actions(assigned_user_id)")


def get_action_by_id(action_id):
    row = get_db().execute(ACTION_SELECT + " WHERE ra.action_id = ?", (action_id,)).fetchone()
    return dict(row) if row is not None else None


def get_actions(playbook_id):
    rows = get_db().execute(
        ACTION_SELECT + " WHERE ra.playbook_id = ? ORDER BY ra.step_number", (playbook_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def unfinished_earlier_steps(playbook_id, step_number):
    rows = get_db().execute(
        """SELECT step_number FROM response_actions
           WHERE playbook_id = ? AND step_number < ? AND status != 'Completed' ORDER BY step_number""",
        (playbook_id, step_number),
    ).fetchall()
    return [row[0] for row in rows]


def insert_action(playbook_id, data):
    cursor = get_db().execute(
        """INSERT INTO response_actions (playbook_id, action_description, step_number, assigned_user_id)
           VALUES (?, ?, ?, ?)""",
        (playbook_id, data["action_description"], data["step_number"], data["assigned_user_id"]),
    )
    return get_action_by_id(cursor.lastrowid)


def update_action(action_id, updates):
    assignments = ", ".join(f"{field} = ?" for field in updates)
    get_db().execute(
        f"UPDATE response_actions SET {assignments} WHERE action_id = ?",
        (*updates.values(), action_id),
    )
    return get_action_by_id(action_id)
