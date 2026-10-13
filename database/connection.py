"""SQLite connections shared by the table modules."""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from flask import current_app, g


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def get_db():
    if "db" not in g:
        path = Path(current_app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(path, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()
