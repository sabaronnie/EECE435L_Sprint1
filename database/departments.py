from database.connection import get_db


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS departments (
        department_id INTEGER PRIMARY KEY,
        name TEXT NOT NULL COLLATE NOCASE UNIQUE
            CHECK (length(trim(name)) BETWEEN 1 AND 100)
    )""")


def get_or_create_department(name):
    get_db().execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (name,))
    return get_db().execute(
        "SELECT department_id FROM departments WHERE name = ?", (name,)
    ).fetchone()[0]
