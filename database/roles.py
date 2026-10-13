ROLES = ("SECURITY_ADMINISTRATOR", "SECURITY_ANALYST", "REGULAR_USER", "AUDITOR")


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS roles (
        role_id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE CHECK (name IN (
            'SECURITY_ADMINISTRATOR', 'SECURITY_ANALYST', 'REGULAR_USER', 'AUDITOR'
        ))
    )""")
    conn.executemany("INSERT OR IGNORE INTO roles (name) VALUES (?)", [(r,) for r in ROLES])
