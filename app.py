"""Flask app setup shared by the project services."""

import os
from pathlib import Path

import click
from flask import Flask
from flask_cors import CORS

from database import close_db, create_db_tables
from services import register_services


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(__file__).parent / "instance" / "database.db")),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
    if origins:
        CORS(app, resources={r"/api/*": {"origins": origins}})
    app.teardown_appcontext(close_db)
    with app.app_context():
        create_db_tables()

    @app.cli.command("init-db")
    def init_db_command():
        """Create missing tables without deleting existing records."""
        create_db_tables()
        click.echo("Database tables are ready.")

    register_services(app)
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000)
