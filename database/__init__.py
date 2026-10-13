"""Create all project tables in dependency order without removing existing data."""

from database.connection import close_db, get_db


def create_db_tables():
    from database import (
        roles, departments, users, auth_sessions, assets, incidents,
        investigation_notes, threats, logs, vulnerabilities, notifications,
        playbooks, response_actions,
    )

    with get_db():
        for table in (
            roles, departments, users, auth_sessions, assets, incidents,
            investigation_notes, threats, logs, vulnerabilities, notifications,
            playbooks, response_actions,
        ):
            table.create_table(get_db())


__all__ = ["create_db_tables", "get_db", "close_db"]
