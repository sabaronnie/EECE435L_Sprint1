from database.connection import get_db
from database.departments import get_or_create_department


ASSET_SELECT = """SELECT a.*, d.name AS department,
                         u.username AS owner_username, u.full_name AS owner_name
                  FROM assets a JOIN departments d USING (department_id)
                  JOIN users u ON a.owner_id = u.user_id"""


def create_table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS assets (
        asset_id INTEGER PRIMARY KEY,
        asset_name TEXT NOT NULL CHECK (length(trim(asset_name)) > 0),
        asset_type TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        operating_system TEXT,
        owner_id INTEGER NOT NULL REFERENCES users(user_id),
        department_id INTEGER NOT NULL REFERENCES departments(department_id),
        location TEXT,
        criticality_level TEXT NOT NULL CHECK (criticality_level IN ('Low', 'Medium', 'High', 'Critical')),
        status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'Under Maintenance'))
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner_id)")


def get_asset_by_id(asset_id):
    row = get_db().execute(ASSET_SELECT + " WHERE a.asset_id = ?", (asset_id,)).fetchone()
    return dict(row) if row is not None else None


def insert_asset(data):
    department_id = get_or_create_department(data["department"])
    cursor = get_db().execute(
        """INSERT INTO assets (asset_name, asset_type, ip_address, operating_system,
           owner_id, department_id, location, criticality_level, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (data["asset_name"], data["asset_type"], data["ip_address"], data["operating_system"],
         data["owner_id"], department_id, data["location"], data["criticality_level"], data["status"]),
    )
    return get_asset_by_id(cursor.lastrowid)


def update_asset(asset_id, data):
    department_id = get_or_create_department(data["department"])
    get_db().execute(
        """UPDATE assets SET asset_name = ?, owner_id = ?, department_id = ?,
           criticality_level = ?, status = ? WHERE asset_id = ?""",
        (data["asset_name"], data["owner_id"], department_id,
         data["criticality_level"], data["status"], asset_id),
    )
    return get_asset_by_id(asset_id)


def delete_asset(asset_id):
    return get_db().execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,)).rowcount
