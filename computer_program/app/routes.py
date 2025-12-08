from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from app import db
from app.models import User
from app.forms import LoginForm, RegisterForm, ChangePasswordForm
from functools import wraps

main = Blueprint('main', __name__)

def role_required(required_role):
    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            if 'user' not in session:
                current_app.logger.error('Access denied (user not logged in) | required role: %s | ip=%s |',
                                         required_role, request.remote_addr)
                flash('Please log in.', 'error')
                return redirect(url_for('main.login'))

            role = session.get('role')
            username = session.get('user')


            if session.get('role') != required_role:
                current_app.logger.warning("Access denied (incorrect role) | user=%s | role=%s | required=%s "
                                           "| ip=%s",username, role, required_role, request.remote_addr)
                abort(403)
            return view_function(*args, **kwargs)
        return wrapped_view
    return decorator

def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if 'user' not in session:
            current_app.logger.error('Access denied (user not logged in) |  ip=%s |',request.remote_addr)
            flash('Please log in.', 'error')
            return redirect(url_for('main.login'))
        return view_function(*args, **kwargs)
    return wrapped_view

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # make email address consistent
        username = form.username.data.strip().lower()
        password = form.password.data

        # lookup user by email address
        user = User.query.filter_by(username=username).first()

        # check hashed password
        if user and user.check_password(password):
            # clear pre-existing data
            session.clear()
            session['user'] = user.username
            session['role'] = user.role

            current_app.logger.info('Login Successful | user=%s | role=%s | ip=%s |',
                                    user.username, user.role, request.remote_addr)

            flash('Login Successful', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            current_app.logger.info('Login Unsuccessful | user=%s | ip=%s |',
                                    username, request.remote_addr)

            flash('Login Unsuccessful, please try again', 'error')

    return render_template('login.html', form=form)


@main.route('/dashboard')
@login_required
def dashboard():
    # load the current user from the database
    user = User.query.filter_by(username=session['user']).first()
    # security double-check
    if not user:
        flash('User not found', 'error')
        session.clear()
        return redirect(url_for('main.login'))

    # using get_bio() from models to decrypt and return safe bio
    return render_template('dashboard.html', username=user.username, bio=user.get_bio())


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data
        bio = form.bio.data

        # check email isn't already registered
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            current_app.logger.warning("Registration failed (email exists) | username=%s | ip=%s",
                                       username, request.remote_addr)
            flash(f"An account with the email address '{username}' already exists", "error")
            return render_template('register.html', form=form)

        user = User(username=username, password=password, role='user', bio=bio)
        db.session.add(user)
        db.session.commit()

        current_app.logger.info("Registration successful | username=%s | role=%s | ip=%s",
            user.username,user.role, request.remote_addr)
        flash('Registration Successful', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)


@main.route('/admin-panel')
@role_required('admin')
def admin():
    return render_template('admin.html')

@main.route('/moderator')
@role_required('moderator')
def moderator():
    return render_template('moderator.html')

@main.route('/user-dashboard')
@role_required('user')
def user_dashboard():
    user = User.query.filter_by(username=session.get('user')).first()
    # security double-check
    if not user:
        flash('User not found.', 'error')
        session.clear()
        return redirect(url_for('main.login'))

    return render_template('user_dashboard.html', username=user.username, bio=user.get_bio())


@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    user = User.query.filter_by(username=session.get('user')).first()
    if not user:
        current_app.logger.warning("Change password failed (user not found) | session_user=%s | ip=%s",
            session.get('user'), request.remote_addr)
        flash('User not found.', 'error')
        session.clear()
        return redirect(url_for('main.login'))

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        # check current password against the hashed password
        if not user.check_password(current_password):
            current_app.logger.warning("Change password failed (wrong current password) | user=%s | ip=%s",
                user.username, request.remote_addr)
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', form=form)

        # check the new password is different to the current password
        if user.check_password(new_password):
            current_app.logger.warning(
                "Change password failed (new password same as old) | user=%s | ip=%s",
                user.username, request.remote_addr)
            flash("New password must be different from your current password.", "error")
            return render_template('change_password.html', form=form)

        # hash and pepper the new password
        user.set_password(new_password)
        db.session.commit()

        current_app.logger.info("Password changed successfully | user=%s | ip=%s",
            user.username, request.remote_addr)
        flash('Your password has been changed.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html', form=form)


