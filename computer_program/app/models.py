import html
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from app import db


def _get_fernet():
    # get encryption key from flask config, loaded from an environment variable in config.py
    key = current_app.config.get['FERNET_KEY']
    # in order to avoid running insecurely, end the program
    if not key:
        raise RuntimeError('FERNET_KEY has not been set in the environment')
    # if flask stored key as string, convert to bytes (fernet requirement)
    if isinstance(key, str):
        key = key.encode('utf-8')
    return Fernet(key)

def sanitise_bio(raw_bio):
    if raw_bio is None:
        return ""
    return html.escape(raw_bio.strip(), quote = True) # translate the HTML to safe plain text

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # email address is allowed up to 254 characters
    username = db.Column(db.String(254), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    #Encrypted biography, Text is safer than fixed length string
    bio = db.Column(db.Text, nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.set_password(password) # hash and pepper
        self.role = role
        self.set_bio(bio) # sanitised and encrypted

    def set_password(self, password):
        pepper = current_app.config.get("PASSWORD_PEPPER", "")
        # combine the raw password and pepper before hashing
        unsafe_password = (password or "") + pepper
        self.password = generate_password_hash(unsafe_password)









