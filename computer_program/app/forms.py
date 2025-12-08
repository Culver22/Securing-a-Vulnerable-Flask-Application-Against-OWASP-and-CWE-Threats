import re
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import (DataRequired, Length, EqualTo, ValidationError, Regexp, length)
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

    # enforce password rules on all password fields

    # length must be >= 10
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

class LoginForm(FlaskForm):
    username = StringField("Email", validators=[DataRequired(message="Email address is required"),
                                                Length(max=254),
                                                Regexp(email_regex, message="Please enter a valid email address.")])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    username = StringField("Email", validators=[DataRequired(message="Email is required."), Length(max=254),
                                                Regexp(email_regex, message="Please enter a valid email address.")])
    password = PasswordField("Password",
        validators=[DataRequired(message="Password is required."), validate_password])

    confirm_password = PasswordField("Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")])

    bio = TextAreaField("Biography", validators=[DataRequired(message="Biography is required."),
            Length(min=1, max=1000, message="Biography must be between 1 and 1000 characters long.")])

    submit = SubmitField("Register")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])

    new_password = PasswordField("New Password", validators=[DataRequired(), validate_password])

    confirm_new_password = PasswordField("Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password", message="New passwords must match.")])

    submit = SubmitField("Change Password")
