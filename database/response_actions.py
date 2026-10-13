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
