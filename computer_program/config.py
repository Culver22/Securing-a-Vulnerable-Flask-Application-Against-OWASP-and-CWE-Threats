from datetime import timedelta
import os

class Config:

    # SQLite db
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session security flags
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # expire session after 30 minutes
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

class DevConfig(Config):
    DEBUG = True

    # assign session cookies only hard-coded for coursework
    SECRET_KEY = 'dev-secret-key-change-me'

    # used for hashing passwords not stored in the db
    PASSWORD_PEPPER = "dev-pepper-change-me"

    # hard coded to ensure the app runs
    FERNET_KEY = "dev-fernet-key-change-me"

    SESSION_COOKIE_SECURE = False

class ProdConfig(Config):
    DEBUG = False
    # allow cookies over HTTPS
    SESSION_COOKIE_SECURE = True

    # load secrets from environment
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    PASSWORD_PEPPER = os.environ.get("PASSWORD_PEPPER", "")
    FERNET_KEY = os.environ.get("FERNET_KEY", "")

    # Fail if any key cannot be loaded
    if not SECRET_KEY or not PASSWORD_PEPPER or not FERNET_KEY:
        raise RuntimeError("Production secrets must be set in environment variables!")

