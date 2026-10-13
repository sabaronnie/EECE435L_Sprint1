"""Register each completed service with the Flask app."""


def register_services(app):
    from services.users_and_identity_management import users_api, register_commands

    app.register_blueprint(users_api)
    register_commands(app)
