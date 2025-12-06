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





"""
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.password = password
        self.role = role
        self.bio = bio
"""







