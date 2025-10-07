import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
import re
import logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO)

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent access to cookies via JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Mitigate CSRF attacks

# Google reCAPTCHA Secret Key
RECAPTCHA_SECRET_KEY = 'YOUR_SECRET_KEY'  # Replace with your secret key from Google


# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='your_mysql_user',
        password='your_mysql_password',
        database='user_database'
    )


def verify_recaptcha(recaptcha_response):
    """Verify the reCAPTCHA response with Google's verification API"""
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    return result.get('success', False)


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    recaptcha_response = request.form['g-recaptcha-response']

    # Validate user input for SQL Injection and other vulnerabilities
    if not re.match(r'^[a-zA-Z0-9]{3,20}$', username):
        flash('Invalid username format!', 'danger')
        return redirect(url_for('index'))

    if len(password) < 8 or not re.search(r'\d', password):
        flash('Password must be at least 8 characters long and contain at least one number', 'danger')
        return redirect(url_for('index'))

    # Verify the reCAPTCHA response using if-else
    if verify_recaptcha(recaptcha_response):
        # If CAPTCHA is verified, proceed with the login logic
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        # Check if user exists and verify the password
        if user:
            if check_password_hash(user['password'], password):
                # Reset failed attempts on successful login
                cursor.execute('UPDATE users SET failed_attempts = 0 WHERE username = %s', (username,))
                conn.commit()
                session.pop('failed_attempts', None)  # Clear failed attempts from session
                session.pop('last_attempt_time', None)  # Clear timestamp from session
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Handle incorrect password
                new_failed_attempts = user['failed_attempts'] + 1
                cursor.execute('UPDATE users SET failed_attempts = %s, last_failed_attempt = NOW() WHERE username = %s',
                               (new_failed_attempts, username))
                conn.commit()

                # Track failed attempts in session
                session['failed_attempts'] = new_failed_attempts
                session['last_attempt_time'] = datetime.now()

                if new_failed_attempts >= 3:
                    flash('Too many failed attempts. Please try again later.', 'danger')
                else:
                    flash('Invalid username or password.', 'danger')

                return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('index'))
    else:
        # If CAPTCHA fails
        flash('reCAPTCHA verification failed. Please try again.', 'danger')
        return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(debug=True)
