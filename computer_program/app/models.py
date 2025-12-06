import html
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from app import db


def _get_fernet():
    # get encryption key from flask config, loaded from an environment variable in config.py
    key = current_app.config.get["FERNET_KEY"]
    # in order to avoid running insecurely, end the program
    if not key:
        raise RuntimeError('FERNET_KEY has not been set in the environment')
    # if flask stored key as string, convert to bytes (fernet requirement)
    if isinstance(key, str):
        key = key.encode('utf-8')
    return Fernet(key)

def sanitise_bio(raw_bio):
    # escape all HTML the user has provided so that it is treated as plain text
    if raw_bio is None:
        return ""
    return html.escape(raw_bio.strip(), quote = True)

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
        # hash password (using PBKDF2). salt is added automatically, pepper added from config

        pepper = current_app.config.get("PASSWORD_PEPPER", "")
        # combine the raw password and pepper before hashing
        unsafe_password = (password or "") + pepper
        self.password = generate_password_hash(unsafe_password)

    def check_password(self, password):
        # verify the unsafe password against the hashed password

        pepper = current_app.config.get("PASSWORD_PEPPER", "")
        unsafe_password = (password or "") + pepper
        return check_password_hash(self.password, unsafe_password)

    def set_bio(self, bio):
        # sanitise and encrypt bio before storing

        safe_bio = sanitise_bio(bio)
        fernet = _get_fernet()
        encrypted = fernet.encrypt(safe_bio.encode('utf-8'))
        # encrypt bio to bytes, then decode to a UTF-8 string which can be safely stored in the db
        self.bio = encrypted.decode('utf-8')

    def get_bio(self):
        # decrypt and return the stored bio as safe text

        if not self.bio:
            # return a safe blank biography
            return ""
        fernet = _get_fernet()
        try:
            decrypted_bio = fernet.decrypt(self.bio.encode('utf-8'))
            return decrypted_bio.decode('utf-8')
        except InvalidToken:
            return ""










