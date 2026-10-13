def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS departments (
        department_id INTEGER PRIMARY KEY,
        name TEXT NOT NULL COLLATE NOCASE UNIQUE
            CHECK (length(trim(name)) BETWEEN 1 AND 100)
    )""")
