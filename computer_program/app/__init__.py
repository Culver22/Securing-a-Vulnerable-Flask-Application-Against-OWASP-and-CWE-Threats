from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    @app.errorhandler(400)
    def bad_request(error):
        return render_template('400.html'), 400

    @app.errorhandler(403)
    def forbidden(error):
        # user does not have permission to access content
        return render_template('403.html'), 403

    @app.errorhandler(404)
    def page_not_found(error):
        # page doesn't exist
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        # error within the server, don't show debug info
        return render_template('500.html'), 500

    with app.app_context():
        db.drop_all()
        db.create_all()

        from .models import User
        db.session.add(User("admin@example.com", "Admin123!", "admin", "Admin user."))
        db.session.add(User("moderator@example.com", "Mod123!!!", "moderator", "Moderator user."))
        db.session.add(User("user@example.com", "User123!!!", "user", "Normal user."))
        db.session.commit()

    return app

