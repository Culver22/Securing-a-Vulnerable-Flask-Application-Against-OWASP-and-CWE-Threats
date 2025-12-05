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