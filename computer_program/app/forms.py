import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import (DataRequired, Length, EqualTo, ValidationError, Regexp)
from flask import current_app

Password_Blacklist = {"Password123$", "Qwerty123!", "Adminadmin1@", "weLcome123!"}
