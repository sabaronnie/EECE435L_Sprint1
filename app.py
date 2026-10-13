"""Flask app setup shared by the project services."""

import os
from pathlib import Path
import sqlite3

import click
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from auth import authenticate
from database import close_db, create_db_tables, get_db
from database.logs import record_activity
from errors import ApiError
from services import register_services


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(__file__).parent / "instance" / "database.db")),
        MAX_CONTENT_LENGTH=16 * 1024,
        TOKEN_TTL_SECONDS=3600,
        DUMMY_PASSWORD_HASH=generate_password_hash("Dummy-check-only-1!", method="scrypt"),
    )
    if test_config:
        app.config.update(test_config)
    origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
    if origins:
        CORS(app, resources={r"/api/*": {"origins": origins}})
    app.teardown_appcontext(close_db)
    with app.app_context():
        create_db_tables()

    @app.before_request
    def load_identity():
        authenticate()

    @app.errorhandler(ApiError)
    def api_error(error):
        get_db().rollback()
        if error.code == 403:
            record_activity(getattr(g, "actor", None), "PERMISSION_DENIED",
                            f"{request.method} {request.path}", "Warning")
        body = {"status": "error", "message": error.message}
        if error.details is not None:
            body["details"] = error.details
        return jsonify(body), error.code

    @app.errorhandler(sqlite3.IntegrityError)
    def database_error(error):
        get_db().rollback()
        if "UNIQUE constraint failed" in str(error):
            message = "Username or email already exists"
        elif "FOREIGN KEY constraint failed" in str(error):
            message = "User is still linked to other records and cannot be deleted"
        else:
            message = "The change conflicts with a database rule"
        return jsonify(status="error", message=message), 409

    @app.errorhandler(HTTPException)
    def http_error(error):
        get_db().rollback()
        return jsonify(status="error", message=error.description), error.code

    @app.errorhandler(Exception)
    def server_error(error):
        get_db().rollback()
        app.logger.exception("Request failed")
        return jsonify(status="error", message="An unexpected server error occurred"), 500

    @app.after_request
    def response_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.cli.command("init-db")
    def init_db_command():
        """Create missing tables without deleting existing records."""
        create_db_tables()
        click.echo("Database tables are ready.")

    register_services(app)
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000)
