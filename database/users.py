"""User table and parameterized queries, following Lab 5."""

from database.connection import get_db, utc_now


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        full_name TEXT NOT NULL CHECK (length(trim(full_name)) BETWEEN 1 AND 120),
        username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(username) BETWEEN 3 AND 50),
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        department_id INTEGER NOT NULL REFERENCES departments(department_id),
        role_id INTEGER NOT NULL REFERENCES roles(role_id),
        account_status TEXT NOT NULL DEFAULT 'Active'
            CHECK (account_status IN ('Active', 'Inactive', 'Suspended')),
        created_at TEXT NOT NULL,
        last_login_at TEXT
    )""")


class UserRepository:
    SELECT = """SELECT u.*, r.name AS role, d.name AS department
                FROM users u JOIN roles r USING (role_id)
                JOIN departments d USING (department_id)"""

    def by_id(self, user_id):
        return get_db().execute(self.SELECT + " WHERE u.user_id = ?", (user_id,)).fetchone()

    def by_username(self, username):
        return get_db().execute(self.SELECT + " WHERE u.username = ?", (username,)).fetchone()

    def by_identifier(self, identifier):
        return get_db().execute(
            self.SELECT + " WHERE u.username = ? OR u.email = ?", (identifier, identifier)
        ).fetchone()

    def all(self):
        return get_db().execute(self.SELECT + " ORDER BY u.user_id").fetchall()

    def department_id(self, name):
        get_db().execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (name,))
        return get_db().execute(
            "SELECT department_id FROM departments WHERE name = ?", (name,)
        ).fetchone()[0]

    def role_id(self, name):
        return get_db().execute("SELECT role_id FROM roles WHERE name = ?", (name,)).fetchone()[0]

    def insert(self, data, password_hash):
        cursor = get_db().execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, department_id, role_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (data["full_name"], data["username"], data["email"], password_hash,
             self.department_id(data["department"]), self.role_id(data["role"]), utc_now()),
        )
        return self.by_id(cursor.lastrowid)


def public_user(user):
    fields = (
        "user_id", "full_name", "username", "email", "department", "role",
        "account_status", "created_at", "last_login_at",
    )
    return {field: user[field] for field in fields}
