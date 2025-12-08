from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from config import DevConfig

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(DevConfig)

    db.init_app(app)

    from app.routes import main
    app.register_blueprint(main)

    @app.after_request
    def apply_security_headers(response):
        # stops browsers guessing content types
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        # stops the site being put in an iframe - clickjacking
        response.headers.setdefault("X-Frame-Options", "DENY")
        # do not leak URLs in the Referer header
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # only allow content from this server (mitigates cross site scripting)
        response.headers.setdefault("Content-Security-Policy default-src 'self'; script-src 'self'; style-src 'self';"
                                                               " object-src 'none'; base-uri 'self';"
                                                               " frame-ancestors 'none'")
        # tell browser to prefer HTTPS (for production use)
        response.headers.setdefault("Strict-Transport-Security max-age=31536000; includeSubDomains")
        return response

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

