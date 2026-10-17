"""Flask app setup shared by the project services."""

import os
from pathlib import Path
import sqlite3

import click
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from auth import (
    ADMIN, ANALYST, AUDITOR, REGULAR, admin_required, login_required,
    incident_access_required, own_profile_required, registration_allowed, roles_required,
)
from database import close_db, create_db_tables, get_db
from database.logs import record_activity
from errors import ApiError
from services import (
    audit_logging, assets_management, incidents_management, reports_management,
    threats_management, users_management,
)

USERS_URL = "/api/RonnieSaba/users"
ASSETS_URL = "/api/RonnieSaba/assets"
INCIDENTS_URL = "/api/RonnieSaba/incidents"
THREATS_URL = "/api/TracyGhosn/threats"
LOGS_URL = "/api/TracyGhosn/logs"
REPORTS_URL = "/api/TracyGhosn/reports"


app = Flask(__name__)
app.config.from_mapping(
    DATABASE=os.environ.get("DATABASE_PATH", str(Path(__file__).parent / "instance" / "database.db")),
    MAX_CONTENT_LENGTH=16 * 1024,
    TOKEN_TTL_SECONDS=3600,
    DUMMY_PASSWORD_HASH=generate_password_hash("Dummy-check-only-1!", method="scrypt"),
)
origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
if origins:
    CORS(app, resources={r"/api/*": {"origins": origins}})
app.teardown_appcontext(close_db)
with app.app_context():
    create_db_tables()


@app.errorhandler(ApiError)
def api_error(error):
    get_db().rollback()
    if error.code in (401, 403) and not request.path.startswith(USERS_URL + "/login"):
        if request.path.startswith(INCIDENTS_URL):
            service_name = "Incident Management"
        elif request.path.startswith(ASSETS_URL):
            service_name = "Asset Management"
        elif request.path.startswith(THREATS_URL):
            service_name = "Threat Intelligence"
        elif request.path.startswith(LOGS_URL):
            service_name = "Security Audit Logging"
        else:
            service_name = "Users and Identity Management"
        action = "AUTHENTICATION_FAILED" if error.code == 401 else "PERMISSION_DENIED"
        record_activity(getattr(g, "actor", None), action,
                        f"HTTP {error.code}: {request.method} {request.path}", "Warning",
                        related_service=service_name)
    body = {"status": "error", "message": error.message}
    if error.details is not None:
        body["details"] = error.details
    return jsonify(body), error.code


@app.errorhandler(sqlite3.IntegrityError)
def database_error(error):
    get_db().rollback()
    if "UNIQUE constraint failed: threats.threat_type, threats.threat_value" in str(error):
        message = "A threat indicator with this type and value already exists"
    elif "UNIQUE constraint failed" in str(error):
        message = "Username or email already exists"
    elif "FOREIGN KEY constraint failed" in str(error):
        if request.path.startswith(ASSETS_URL) and request.method == "DELETE":
            message = "Asset is still linked to incidents or vulnerabilities and cannot be deleted"
        elif request.path.startswith(INCIDENTS_URL):
            message = "A referenced user or asset is no longer available"
        else:
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


@app.route(USERS_URL + "/register", methods=["POST"])
@registration_allowed
def register_user():
    user = users_management.register_user(request.get_json(), g.actor)
    return jsonify(status="success", message="User registered successfully", user=user), 201


@app.route(USERS_URL + "/login", methods=["POST"])
def login_user():
    result = users_management.login_user(request.get_json())
    return jsonify(status="success", message="Authentication successful", **result)


@app.route(USERS_URL + "/logout", methods=["POST"])
@login_required
def logout_user():
    users_management.logout_user(g.session_id, g.actor)
    return jsonify(status="success", message="Logged out successfully")


@app.route(USERS_URL, methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def list_users():
    return jsonify(status="success", users=users_management.list_users())


@app.route(USERS_URL + "/<username>", methods=["GET"])
@roles_required(ADMIN, AUDITOR, REGULAR)
@own_profile_required
def get_user(username):
    user = users_management.get_user(username)
    return jsonify(status="success", user=user)


@app.route(USERS_URL + "/<int:user_id>", methods=["PUT"])
@roles_required(ADMIN, REGULAR)
@own_profile_required
def update_user(user_id):
    user = users_management.update_user(user_id, request.get_json(), g.actor)
    return jsonify(status="success", message="User updated successfully", user=user)


@app.route(USERS_URL + "/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    users_management.delete_user(user_id, g.actor)
    return jsonify(status="success", message="User deleted successfully")


@app.route(USERS_URL + "/<int:user_id>/role", methods=["PUT"])
@admin_required
def change_role(user_id):
    user = users_management.change_role(user_id, request.get_json(), g.actor)
    return jsonify(status="success", message="User role updated successfully", user=user)


@app.route(USERS_URL + "/<int:user_id>/status", methods=["PUT"])
@admin_required
def change_status(user_id):
    user = users_management.change_status(user_id, request.get_json(), g.actor)
    return jsonify(status="success", message="Account status updated successfully", user=user)


@app.route(ASSETS_URL, methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def list_assets():
    return jsonify(status="success", assets=assets_management.list_assets())


@app.route(ASSETS_URL, methods=["POST"])
@admin_required
def create_asset():
    asset = assets_management.create_asset(request.get_json(), g.actor)
    return jsonify(status="success", message="Asset created successfully", asset=asset), 201


@app.route(ASSETS_URL + "/search", methods=["GET"])
@roles_required(ADMIN, ANALYST, AUDITOR)
def search_assets():
    assets = assets_management.search_assets(request.args.to_dict())
    return jsonify(status="success", assets=assets)


@app.route(ASSETS_URL + "/<int:asset_id>", methods=["GET"])
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_asset(asset_id):
    asset = assets_management.get_asset(asset_id)
    return jsonify(status="success", asset=asset)


@app.route(ASSETS_URL + "/<int:asset_id>", methods=["PUT"])
@admin_required
def update_asset(asset_id):
    asset = assets_management.update_asset(asset_id, request.get_json(), g.actor)
    return jsonify(status="success", message="Asset updated successfully", asset=asset)


@app.route(ASSETS_URL + "/<int:asset_id>", methods=["DELETE"])
@admin_required
def delete_asset(asset_id):
    assets_management.delete_asset(asset_id, g.actor)
    return jsonify(status="success", message="Asset deleted successfully")


@app.route(INCIDENTS_URL, methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def list_incidents():
    return jsonify(status="success", incidents=incidents_management.list_incidents())


@app.route(THREATS_URL, methods=["GET"])
@roles_required(ADMIN, ANALYST, AUDITOR)
def list_threats():
    return jsonify(status="success", threats=threats_management.list_threats())


@app.route(THREATS_URL, methods=["POST"])
@admin_required
def create_threat():
    threat = threats_management.create_threat(request.get_json(), g.actor)
    return jsonify(status="success", message="Threat indicator added successfully", threat=threat), 201


@app.route(THREATS_URL + "/search", methods=["GET"])
@roles_required(ADMIN, ANALYST)
def search_threats():
    return jsonify(status="success", threats=threats_management.search_threats(request.args.to_dict()))


@app.route(THREATS_URL + "/<int:threat_id>", methods=["GET"])
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_threat(threat_id):
    return jsonify(status="success", threat=threats_management.get_threat(threat_id))


@app.route(THREATS_URL + "/<int:threat_id>", methods=["PUT"])
@admin_required
def update_threat(threat_id):
    threat = threats_management.update_threat(threat_id, request.get_json(), g.actor)
    return jsonify(status="success", message="Threat information updated successfully", threat=threat)


@app.route(THREATS_URL + "/<int:threat_id>", methods=["DELETE"])
@admin_required
def delete_threat(threat_id):
    threats_management.delete_threat(threat_id, g.actor)
    return jsonify(status="success", message="Threat indicator deleted successfully")


@app.route(LOGS_URL, methods=["POST"])
@admin_required
def create_log():
    log = audit_logging.create_log(request.get_json())
    return jsonify(status="success", message="Audit log created successfully", log=log), 201


@app.route(LOGS_URL, methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def list_logs():
    return jsonify(status="success", logs=audit_logging.list_logs())


@app.route(LOGS_URL + "/search", methods=["GET"])
@roles_required(ADMIN, AUDITOR, ANALYST)
def search_logs():
    return jsonify(status="success", logs=audit_logging.search_logs(request.args.to_dict()))


@app.route(LOGS_URL + "/user/<int:user_id>", methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def get_logs_for_user(user_id):
    return jsonify(status="success", logs=audit_logging.logs_for_user(user_id))


@app.route(LOGS_URL + "/<int:log_id>", methods=["GET"])
@roles_required(ADMIN, AUDITOR, ANALYST)
def get_log(log_id):
    return jsonify(status="success", log=audit_logging.get_log(log_id))


@app.route(LOGS_URL + "/<int:log_id>", methods=["DELETE"])
@admin_required
def delete_log(log_id):
    audit_logging.delete_log(log_id, g.actor)
    return jsonify(status="success", message="Audit log deleted successfully")


@app.route(REPORTS_URL + "/summary", methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def security_summary_report():
    return jsonify(status="success", report=reports_management.summary_report())


@app.route(REPORTS_URL + "/incidents", methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def incident_report():
    return jsonify(status="success", report=reports_management.incident_report())


@app.route(REPORTS_URL + "/assets", methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def asset_report():
    return jsonify(status="success", report=reports_management.asset_report())


@app.route(REPORTS_URL + "/threats", methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def threat_report():
    return jsonify(status="success", report=reports_management.threat_report())


@app.route(REPORTS_URL + "/vulnerabilities", methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def vulnerability_report():
    return jsonify(status="success", report=reports_management.vulnerability_report())


@app.route(REPORTS_URL + "/activity", methods=["GET"])
@roles_required(ADMIN, AUDITOR)
def activity_report():
    return jsonify(status="success", report=reports_management.activity_report())


@app.route(INCIDENTS_URL, methods=["POST"])
@roles_required(ADMIN, REGULAR)
def create_incident():
    incident = incidents_management.create_incident(request.get_json(), g.actor)
    return jsonify(status="success", message="Incident created successfully", incident=incident), 201


@app.route(INCIDENTS_URL + "/<int:incident_id>", methods=["GET"])
@roles_required(ADMIN, ANALYST, AUDITOR, REGULAR)
@incident_access_required
def get_incident(incident_id):
    incident = incidents_management.get_incident(incident_id)
    return jsonify(status="success", incident=incident)


@app.route(INCIDENTS_URL + "/<int:incident_id>/assign", methods=["PUT"])
@admin_required
def assign_incident(incident_id):
    incident = incidents_management.assign_incident(incident_id, request.get_json(), g.actor)
    return jsonify(status="success", message="Incident assigned successfully", incident=incident)


@app.route(INCIDENTS_URL + "/<int:incident_id>/status", methods=["PUT"])
@roles_required(ADMIN, ANALYST)
@incident_access_required
def update_incident_status(incident_id):
    incident = incidents_management.update_status(incident_id, request.get_json(), g.actor)
    return jsonify(status="success", message="Incident status updated successfully", incident=incident)


@app.route(INCIDENTS_URL + "/<int:incident_id>/notes", methods=["POST"])
@roles_required(ADMIN, ANALYST)
@incident_access_required
def add_investigation_note(incident_id):
    note = incidents_management.add_note(incident_id, request.get_json(), g.actor)
    return jsonify(status="success", message="Investigation note added successfully", note=note), 201


@app.cli.command("init-db")
def init_db_command():
    """Create missing tables without deleting existing records."""
    create_db_tables()
    click.echo("Database tables are ready.")


@app.cli.command("create-admin")
@click.option("--full-name", prompt=True)
@click.option("--username", prompt=True)
@click.option("--email", prompt=True)
@click.option("--department", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_admin(full_name, username, email, department, password):
    """Create the first administrator through a trusted local command."""
    try:
        user = users_management.create_admin(dict(
            full_name=full_name, username=username, email=email,
            department=department, password=password,
        ))
    except (ApiError, sqlite3.IntegrityError) as error:
        get_db().rollback()
        message = error.message if isinstance(error, ApiError) else "Username or email already exists"
        raise click.ClickException(message) from error
    click.echo(f"Administrator {user['username']} created.")


if __name__ == "__main__":
    app.run()
