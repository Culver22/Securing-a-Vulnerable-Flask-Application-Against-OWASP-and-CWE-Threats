class Config:
    DEBUG = True
    SECRET_KEY = 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PASSWORD_PEPPER = "dev-pepper-change-me"
    # hard coded Fernet key, to allow the app to run
    # for actual implementation must be set via environment variables
    FERNET_KEY = "dev-fernet-key-change-me"

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # set true when using HTTPS