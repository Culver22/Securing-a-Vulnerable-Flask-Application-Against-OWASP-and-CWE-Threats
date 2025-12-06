import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from app import db
from app.models import User
from app.forms import LoginForm, RegisterForm, ChangePasswordForm

main = Blueprint('main', __name__)

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

            flash('Login Successful', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login Unsuccessful, please try again', 'error')

    return render_template('login.html', form=form)


@main.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('main.login'))

    # load the current user from the database
    user = User.query.filter_by(username=session['user']).first()
    # security double-check
    if not user:
        flash('User not found', 'error')
        session.clear()
        return redirect(url_for('main.login'))

    # using get_bio() from models to decrypt and return safe bio
    return render_template('dashboard.html', user=user.username, bio=user.get_bio())


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
            flash('An account with the email address: %s already exists' % username, 'error')
            return render_template('register.html', form=form)

        user = User(username=username, password=password, role='user', bio=bio)
        db.session.add(user)
        db.session.commit()

        flash('Registration Successful', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)


@main.route('/admin-panel')
def admin():
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    user = User.query.filter_by(username=session.get('user')).first()
    # security double-check
    if not user:
        flash('User not found.', 'error')
        session.clear()
        return redirect(url_for('main.login'))

    return render_template('user_dashboard.html', username=user.username, bio=user.get_bio())


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Require basic "login" state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        user = db.session.execute(
            text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{current_password}' LIMIT 1")
        ).mappings().first()

        # Enforce: current password must be valid for user
        if not user:
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        # Enforce: new password must be different from current password
        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        db.session.execute(
            text(f"UPDATE user SET password = '{new_password}' WHERE username = '{username}'")
        )
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')


