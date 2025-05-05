import base64
import hashlib
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user
from sqlalchemy import text
from .models import User
from . import db, app
import bcrypt

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    # Use SQLAlchemy ORM to prevent SQL injection
    user = User.query.filter_by(email=email).first()

    # Check if user exists and verify password with bcrypt
    if not user or not bcrypt.checkpw(
            base64.b64encode(hashlib.sha256(password.encode()).digest()),
            user.password):
        flash('Please check your login details and try again.')
        app.logger.warning("User login failed")
        return redirect(url_for('auth.login'))

    # If authentication passes, login the user
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    
    # Check if user already exists using SQLAlchemy ORM
    user = User.query.filter_by(email=email).first()
    
    if user:  # If a user is found with this email address
        flash('Email address already exists')
        app.logger.debug("User email already exists")
        return redirect(url_for('auth.signup'))
    
    # Hash the password properly
    password_hash = bcrypt.hashpw(
        base64.b64encode(hashlib.sha256(password.encode()).digest()),
        bcrypt.gensalt()
    )
    
    # Create a new user with the form data
    new_user = User(email=email, name=name, password=password_hash)
    
    # Add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))