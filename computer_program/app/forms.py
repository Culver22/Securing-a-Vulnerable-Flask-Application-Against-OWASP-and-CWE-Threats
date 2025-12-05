import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import (DataRequired, Length, EqualTo, ValidationError, Regexp)
from flask import current_app

password_blacklist = {"Password123$", "Qwerty123!", "Adminadmin1@", "weLcome123!"}

# regex follows normal email format: 'oliverculver234@gmail.com'
email_regex = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

def repeated_sequence(password, repeat_len = 3):
    # loop through each character in a password
    for i in range(len(password) - (repeat_len - 1)):
        repeated = True
        # loop through the next character and compare to i
        for j in range(1, repeat_len):
            if password[i] != password[i + j]:
                repeated = False
                break

        if repeated:
            return True

    return False

def validate_password(form, field):
    # "" guards in the event that password or username cannot be retrieved, app won't crash
    password = field.data or ""
    lower_password = password.lower()

    username = ""
    if hasattr(form, "username") and form.username.data:
        username = form.username.data.strip().lower()

    # password conditions
        # length >= 10
    if len(password) < 10:
        raise ValidationError("Password must be at least 10 characters long.")
        # one uppercase letter
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
        # one digit
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one digit.")
        # one special character
    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValidationError("Password must contain at least one special character.")
        # must not contain the username/email
    if username and username in lower_password:
        raise ValidationError("Password must not contain your email address.")
        # blacklist check (case-insensitive)
    if lower_password in {p.lower() for p in password_blacklist}:
        current_app.logger.warning(
            "Blacklisted password attempt | email=%s", username
        )
        raise ValidationError("This password is not allowed. Please choose a different one.")

        # repeated sequence check
    if repeated_sequence(password, repeat_len=3):
        raise ValidationError(
            "Password must not contain repeated character sequences like 'aaa' or '111'."
        )