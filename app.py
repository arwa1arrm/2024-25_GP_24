import re  # Regular expressions
import time
import zipfile
from flask import Flask, render_template, session, url_for, request, redirect, send_file, flash, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime  # For datetime.datetime.utcnow()
from datetime import timedelta  # For timedelta
import io
import pymysql  # Correct import of PyMySQL
import base64
import bcrypt
from functools import wraps
from flask_mail import Mail, Message
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from stegano import lsb
from PIL import Image
from flask import send_from_directory
import mutagen
from mutagen.mp3 import MP3
from mutagen.flac import FLAC
from mutagen.oggvorbis import OggVorbis
from mutagen.easymp4 import EasyMP4
from mutagen.id3 import ID3, COMM
import wave
import struct
from pydub import AudioSegment
from pydub.utils import which
import numpy as np
import subprocess
import hashlib

from werkzeug.utils import quote

from urllib.parse import urlparse

def parse_database_url(url):
    result = urlparse(url)
    return result.username, result.password, result.hostname, result.path[1:]


# Initialize Flask app  and MySQL
app = Flask(__name__)

# Configure the secret key for session management
app.secret_key = 'g5$8^bG*dfK4&2e3yH!Q6j@z'  # Change this before deploying



#*********************** Configure your Flask-Mail****************************#
#************* we used TLC, which is a cryptographic protocol designed to provide secure *******************#
# ******************* communication over a computer network ******************* #
app.config['MAIL_SERVER'] = 'smtp.gmail.com' 
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'concealsafe@gmail.com' 
app.config['MAIL_PASSWORD'] = 'logqznxrmktpxtva'
app.config['MAIL_DEFAULT_SENDER'] = 'concealsafe@gmail.com'  
mail = Mail(app)


#**************************************************************#
#*********************OTP GENERATION***************************#
#**************************************************************#

def generate_otp():
    """Generate a random OTP."""
    return str(random.randint(100000, 999999)) #generate string of 6 digits

def send_otp_email(to_email, otp):
    """Send the OTP to the user's email."""
    msg = Message('Your OTP Code', recipients=[to_email])
    msg.body = f'Your OTP code is: {otp}'
    mail.send(msg)




from urllib.parse import urlparse


def get_database_config():
    """Get database configuration from environment variables or fallback to default."""
    DATABASE_URL = os.environ.get('JAWSDB_URL')
    if DATABASE_URL:
        result = urlparse(DATABASE_URL)
        return {
            'MYSQL_HOST': result.hostname,
            'MYSQL_USER': result.username,
            'MYSQL_PASSWORD': result.password,
            'MYSQL_DB': result.path[1:]  # Removing leading '/' from database name
        }
    return {
        'MYSQL_HOST': 'localhost',
        'MYSQL_USER': 'root',
        'MYSQL_PASSWORD': 'root',
        'MYSQL_DB': 'concealsafe'
    }

# Configure the MySQL connection settings for the app
app.config.update(get_database_config())

def get_db_connection():
    """Function to connect to the MySQL database using PyMySQL."""
    connection = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB'],
        cursorclass=pymysql.cursors.DictCursor  # This ensures that results are returned as dictionaries
    )
    return connection

# Set the session timeout period in seconds (15 minutes)
SESSION_TIMEOUT = 900



#**************************************************************#
#*********************CERTIFICATE GENERATION*******************#
#**************************************************************#

def generate_keys_and_certificate(user_name):
    """Generate RSA keys and self-signed certificate for the user."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, #commonly used
        key_size=2048, #considered safe
        backend=default_backend()
    )
    
    public_key = private_key.public_key() #Public Key Extraction
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user_name)]) #Certificate Subject and Issuer
    
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).serial_number(
        x509.random_serial_number() #Assigns a unique serial number to the certificate
    ).public_key(public_key).sign(private_key, hashes.SHA256(), default_backend()) #Adds the public key to the certificate and signs it using the SHA-256 hashing algorithm with the private key
    
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption() # Converts the private key into a byte format (PEM), which can be easily saved or transmitted.
        # no encryption is applied to the private key
    )
    
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM) # Similarly, converts the certificate into PEM-encoded bytes

    return private_key_bytes, certificate_bytes

#**************************************#
#**********session management**********#
#**************************************#

@app.before_request
def check_session_timeout():
    """This function checks whether a user's session has expired before every request:"""
    if 'last_activity' in session: #Checks if there is a recorded last activity timestamp
        elapsed_time = time.time() - session['last_activity']
        if elapsed_time > SESSION_TIMEOUT:
            session.clear()  # Clear the session
            flash('Session timed out. Please log in again.', 'warning')
            return redirect(url_for('loginsafe'))
        #If the user has been inactive for longer than the timeout,
        # the session is cleared, and they’re redirected to the login page.

    session['last_activity'] = time.time()  # Update last activity time, This timestamp will be checked on the user’s next request.

def login_required(f):
    """to ensure users are authenticated before accessing certain views"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # Check if the user is logged in
            #flash('You need to log in first.', 'warning')
            return redirect(url_for('loginsafe'))  # Redirect to login page if not logged in
        return f(*args, **kwargs)
    return decorated_function

# Prevents browser caching of sensitive pages
#tion adds headers to prevent the browser from caching sensitive pages after a request is processed
@app.after_request
def add_no_cache_headers(response):
    """Ensure pages are not cached."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

#**********************************************************#
#**********************routes******************************#
#**********************************************************#

#**********************************************************#
#**********************Homepage route**********************#
#**********************************************************#
@app.route("/")
def homepage():
    """Render the homepage."""
    return render_template('homepage.html')

#**********************************************************#
#******************userHomepage route**********************#
#**********************************************************#
@app.route("/userHomePage")
@login_required
def userHomePage():
    """Render the user homepage."""
    user_name = session.get('user_name')  # Get the user_name from the session
    return render_template('userHomePage.html', user_name=user_name)




#**********************************************************#
#*****************download_private_key route****************#
#**********************************************************#

@app.route("/download_keys_zip")
@login_required
def download_keys_zip():
    """Allow users to download both their private key and certificate in a zip file."""

    # Retrieve the private key and certificate from session
    private_key_b64 = session.get('private_key')
    certificate = session.get('certificate')

    if private_key_b64 and certificate:
        # Decode the private key from base64
        private_key = base64.b64decode(private_key_b64)

        # Create a ZIP file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add private key to zip
            zip_file.writestr('private_key.pem', private_key)
            # Add certificate (public key) to zip
            zip_file.writestr('public_key.pem', certificate)

        zip_buffer.seek(0)
        return send_file(
            zip_buffer,
            as_attachment=True,
            attachment_filename='keys.zip',  # Change this line
            mimetype='application/zip'
        )
    else:
        flash('One or both keys are not found in your session. Please register again or contact support.', 'danger')
        return redirect(url_for('userHomePage'))

#**********************************************************#
#**********************ForgotPassword route****************#
#**********************************************************#

@app.route("/ForgotPassword", methods=['GET', 'POST'])

def ForgotPassword():
    """Render the Forgot Password page."""
    return render_template('ForgotPassword.html')

#**********************************************************#
#**********************viewprofile route*******************#
#**********************************************************#


@app.route("/viewprofile")
@login_required
def viewprofile():
    """Render the user profile view."""
    user_id = session.get('user_id')  # Get the user_id from the session
    
    # Instead of mysql.connect(), use:
    con = mysql.connection
    cur = con.cursor()
    cur.execute("SELECT user_name, email FROM users WHERE user_id=%s", (user_id,))
    user_data = cur.fetchone()
    cur.close()
    con.close()
    
    if user_data:
        user_name, email = user_data
        return render_template('viewprofile.html', user_name=user_name, email=email)
    else:
        flash('User not found in the database.', 'danger')
        return redirect(url_for('userHomePage'))


#**********************************************************#
#**********************Signup route************************#
#**********************************************************#
@app.route("/signupsafe1", methods=['GET', 'POST'])
def signupsafe1():
    if request.method == "POST":
        user_name = request.form['user_name']
        email = request.form['email']
        password = request.form['password']
        confirmPassword = request.form['confirmPassword']

        # Ensure passwords match
        if password != confirmPassword:
            flash("Passwords do not match.", 'danger')
            return redirect(url_for('signupsafe1'))

        try:
            # Get the database connection using pymysql
            con = get_db_connection()
            cur = con.cursor()
            if request.method == "POST":
                user_name = request.form['user_name']
                email = request.form['email']
                password = request.form['password']
                confirmPassword = request.form['confirmPassword']
            # Check if the email already exists in the DB
            cur.execute("SELECT email FROM users WHERE email=%s", (email,))
            existing_user = cur.fetchone()

            if existing_user:
                flash("Email is already registered! Please log in directly.", 'danger')
                return redirect(url_for('signupsafe1'))

            # Generate keys and certificate
            private_key, certificate = generate_keys_and_certificate(user_name)

            # Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Store private key in the session
            session['private_key'] = base64.b64encode(private_key).decode()
            session['user_id'] = cur.lastrowid  # Store user ID in session

            # Store user details in session
            session['user_name'] = user_name
            session['email'] = email
            session['password'] = password
            session['certificate'] = certificate

            # Generate and send OTP
            otp = generate_otp()
            session['otp'] = otp  # Store OTP in session
            session['email'] = email  # Store email in session
            send_otp_email(email, otp)

            flash('OTP has been sent to your email. Please verify to complete registration.', 'info')
            return redirect(url_for('verify_otp'))

        except Exception as e:
            app.logger.error(f"Error during registration: {e}")
            flash("An error occurred while registering. Please try again.", 'danger')

        finally:
            cur.close()
            con.close()  # Close the connection

    return render_template('signupsafe1.html')

#**********************************************************#
#**********************loginsafe route*******************#
#**********************************************************#    
@app.route("/loginsafe", methods=['GET', 'POST'])
def loginsafe():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        try:
            # Get the database connection using pymysql
            con = get_db_connection()
            cur = con.cursor()
            
            # Check if the user exists in the database
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cur.fetchone()

            if user:
                stored_hashed_password = user['password']  # the password is stored in the 'password' column

                # Check if the hashed password matches the entered password
                if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                    session['user_id'] = user['user_id']
                    session['user_name'] = user['user_name']
                    
                    # Generate and send OTP
                    otp = generate_otp()
                    send_otp_email(email, otp)
                    session['otp'] = otp
                    session['email'] = email
                    
                    flash('OTP has been sent to your email. Please verify to log in.', 'info')
                    return redirect(url_for('verify_login_otp'))  # Redirect to OTP verification page
                else:
                    flash('Invalid email or password.', 'danger')

            else:
                flash('Invalid email or password.', 'danger')

            cur.close()
            con.close()  # Close the connection

        except Exception as e:
            app.logger.error(f"Database error: {e}")
            flash('An error occurred while accessing the database. Please try again later.', 'danger')

    return render_template('loginsafe.html')

#**********************************************************#
#*****************verify_login_otp route*******************#
#**********************************************************#    
@app.route("/verify_login_otp", methods=["GET", "POST"])
#Hnadle OTP verification for login
def verify_login_otp():
    # Check if OTP exists in session for login; if not, redirect to login page
    if "otp" not in session:
        flash("<span style='color:red;'>No OTP found. Please register again.</span>", "warning")
        return redirect(url_for("loginsafe"))  
    
    # Initialize session variables for login
    if "otp_attempts" not in session:
        session["otp_attempts"] = 0
    if "otp_block_until" not in session:
        session["otp_block_until"] = None
    if "cooldown_multiplier" not in session:
        session["cooldown_multiplier"] = 0
    if "otp_resend_count" not in session:
        session["otp_resend_count"] = 0

    # Check if the user is currently blocked due to multiple failed OTP attempts
    if session["otp_block_until"]:
        block_until = session["otp_block_until"]
        if datetime.datetime.utcnow() < block_until:
            block_duration = INITIAL_COOLDOWN_PERIOD + (COOLDOWN_INCREMENT * session["cooldown_multiplier"] - 1)
            flash(f"Too many attempts! Please wait {block_duration} minutes, then click on the link '<span style='color:red;'>RESEND HERE</span>' below to try again.", "danger")
            #return render_template("verify_otp.html")
            return render_template("verify_login_otp.html")

        else:
            # Reset attempt count after cooldown period
            session["otp_attempts"] = 0
            session["otp_block_until"] = None
            session["otp_resend_count"] = 0

    if request.method == "POST":
        otp_entered = request.form["otp"]

        if otp_entered == session["otp"]:
            # OTP is correct, proceed with login logic

           
            user_id = session.get("user_id")
            if user_id:
                return redirect(url_for("userHomePage"))  

            else:
                flash("Session expired. Please try logging in again.", "warning")
                return redirect(url_for("loginsafe")) 

        else:
            # Increment OTP attempt count
            session["otp_attempts"] += 1

            # Check if the max OTP attempts are reached
            if session["otp_attempts"] >= MAX_OTP_ATTEMPTS:
                # Increase cooldown and set block until time
                session["cooldown_multiplier"] += 1
                block_duration = INITIAL_COOLDOWN_PERIOD + (COOLDOWN_INCREMENT * session["cooldown_multiplier"] - 1)
                session["otp_block_until"] = datetime.datetime.utcnow() + timedelta(minutes=block_duration)

                flash(f"Too many attempts! Please wait {block_duration} minutes, then click on the link '<span style='color:red;'>RESEND HERE</span>' below to try again.", "danger")
            else:
                remaining_attempts = MAX_OTP_ATTEMPTS - session["otp_attempts"]
                flash(f"<span style='color:red;'>Invalid OTP. You have {remaining_attempts} attempts left.</span>", "warning")

    return render_template("verify_login_otp.html")

#**********************************************************#
#**********************verify_otp route*******************#
#**********************************************************#    
# Constants
MAX_OTP_ATTEMPTS = 3
INITIAL_COOLDOWN_PERIOD = 1 
COOLDOWN_INCREMENT = 2       

# Constants
MAX_OTP_ATTEMPTS = 3
INITIAL_COOLDOWN_PERIOD = 1
COOLDOWN_INCREMENT = 2

@app.route("/verify_otp", methods=["GET", "POST"])
# Handle OTP verification for registration
def verify_otp():
    if "otp" not in session:
        flash("<span style='color:red;'>No OTP found. Please register again.</span>", "warning")
        return redirect(url_for("signupsafe1"))

    # Initialize session variables if not already set
    if "otp_attempts" not in session:
        session["otp_attempts"] = 0
    if "otp_block_until" not in session:
        session["otp_block_until"] = None
    if "cooldown_multiplier" not in session:
        session["cooldown_multiplier"] = 0
    if "otp_resend_count" not in session:
        session["otp_resend_count"] = 0

    # Check if the user is currently blocked
    if session["otp_block_until"]:
        block_until = session["otp_block_until"]
        if datetime.datetime.utcnow() < block_until:
            # Calculate current block duration based on multiplier (only for verification, not resend)
            block_duration = INITIAL_COOLDOWN_PERIOD + (COOLDOWN_INCREMENT * session["cooldown_multiplier"] - 1)
            flash(f"Too many attempts! Please wait {block_duration} minutes, then click on the link '<span style='color:red;'>RESEND HERE</span>' below to try again.", "danger")
            return render_template("verify_otp.html")
        else:
            # Reset block timer and attempt count after cooldown ends
            session["otp_attempts"] = 0
            session["otp_block_until"] = None
            session["otp_resend_count"] = 0

    if request.method == "POST":
        otp_entered = request.form["otp"]

        if otp_entered == session["otp"]:
            # OTP is correct, now store the user data in the database
            try:
                # Get the database connection using pymysql
                con = get_db_connection()
                cur = con.cursor()

                # Hash the password
                hashed_password = bcrypt.hashpw(session['password'].encode('utf-8'), bcrypt.gensalt())

                # Insert the user data into the database
                cur.execute("INSERT INTO users (user_name, email, password, certificate) VALUES (%s, %s, %s, %s)",
                            (session['user_name'], session['email'], hashed_password.decode('utf-8'), session['certificate'].decode()))
                con.commit()

                # Store the user ID in the session
                session['user_id'] = cur.lastrowid
                session.pop("otp", None)
                session.pop("otp_attempts", None)
                session.pop("otp_block_until", None)
                session.pop("cooldown_multiplier", None)
                session.pop("otp_resend_count", None)

                return render_template("registration_confirmation.html")

            except Exception as e:
                flash(f"Error during registration: {str(e)}", "danger")
                return redirect(url_for("signupsafe1"))

            finally:
                cur.close()
                con.close()  # Ensure the connection is closed

        else:
            # Increment attempt count
            session["otp_attempts"] += 1

            # Check if the max attempts have been reached
            if session["otp_attempts"] >= MAX_OTP_ATTEMPTS:
                # Increment cooldown multiplier and calculate block duration
                session["cooldown_multiplier"] += 1
                block_duration = INITIAL_COOLDOWN_PERIOD + (COOLDOWN_INCREMENT * session["cooldown_multiplier"] - 1)
                session["otp_block_until"] = datetime.datetime.utcnow() + timedelta(minutes=block_duration)

                flash(f"Too many attempts! Please wait {block_duration} minutes, then click on the link '<span style='color:red;'>RESEND HERE</span>' below to try again.", "danger")

            else:
                remaining_attempts = MAX_OTP_ATTEMPTS - session["otp_attempts"]
                flash(f"<span style='color:red;'>Invalid OTP. You have {remaining_attempts} attempts left.</span>", "warning")

    return render_template("verify_otp.html")



#**********************************************************#
#*********************resend_otp route*******************#
#**********************************************************#    
@app.route("/resend_login_otp")
# Handle OTP resend requests for login verification.
def resend_login_otp():
    # Check if the user is allowed to request a new OTP
    if session.get("otp_block_until") and datetime.datetime.utcnow() < session["otp_block_until"]:
        # If the block period has not expired yet, inform the user to wait
        block_until = session["otp_block_until"]
        remaining_time = block_until - datetime.datetime.utcnow()
        remaining_minutes = remaining_time.seconds // 60
        remaining_seconds = remaining_time.seconds % 60

        if remaining_minutes == 0 and remaining_seconds > 0:
            remaining_message = f"'<span style='color:red;'> Please wait for the remaining time: {remaining_seconds} seconds.</span>"
        else:
            remaining_message = f"<span style='color:red;'> Please wait for the remaining time: {remaining_minutes} minutes.</span>"

        flash(f" {remaining_message}", "warning")
        return redirect(url_for('verify_login_otp'))

    # Generate a new OTP for login
    otp = generate_otp()
    session['otp'] = otp  # Store the new OTP in the session

    # Send OTP email for login
    if 'email' in session:  # Assuming email is in session
        send_otp_email(session['email'], otp)
        flash("A new OTP has been sent to your email.", 'info')
    else:
        flash("Error: Email not found. Please try logging in again.", 'danger')
        return redirect(url_for('loginsafe'))  

    return redirect(url_for('verify_login_otp'))


#**********************************************************#
#*********************resend_otp route*********************#
#**********************************************************#  
@app.route("/resend_registration_otp")
# Handle OTP resend requests for registration verification.
def resend_registration_otp():
    """Handle OTP resend requests for registration verification."""
    # Check if the user is allowed to request a new OTP
    if session.get("otp_block_until") and datetime.datetime.utcnow() < session["otp_block_until"]:
        # If the block period has not expired yet, inform the user to wait
        block_until = session["otp_block_until"]
        remaining_time = block_until - datetime.datetime.utcnow()
        remaining_minutes = remaining_time.seconds // 60
        remaining_seconds = remaining_time.seconds % 60

        if remaining_minutes == 0 and remaining_seconds > 0:
            remaining_message = f" <span style='color:red;'> Please wait for the remaining time: {remaining_seconds} seconds.</span>"
        else:
            remaining_message = f" <span style='color:red;'> Please wait for the remaining time: {remaining_minutes} seconds.</span>"

        flash(f" {remaining_message}.", "warning")
        return redirect(url_for('verify_otp'))

    # Generate a new OTP for registration
    otp = generate_otp()
    session['otp'] = otp  # Store the new OTP in the session

    # Send OTP email for registration
    if 'email' in session:  # Assuming email is in session
        send_otp_email(session['email'], otp)
        flash("A new OTP has been sent to your email.", 'info')
    else:
        flash("Error: Email not found. Please try registering again.", 'danger')
        return redirect(url_for('signupsafe1'))  

    return redirect(url_for('verify_otp'))




#**********************************************************#
#***********request_reset_password route*******************#
#**********************************************************#    
@app.route("/request_reset", methods=["POST"])
def request_reset():
    email = request.form["email"]

    # Check if the user exists
    con = mysql.connection
    cur = con.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if user:
        user_id = user[0]  # Get the user's ID

        # Construct the password reset link with user ID
        reset_link = url_for("reset_password", user_id=user_id, _external=True)

        # Send the email
        msg = Message('Password Reset Request', recipients=[email])
        msg.body = f"""
        Hi,

        We received a request to reset your password. You can reset your password by clicking on the link below:

        {reset_link}

        If you did not request a password reset, please ignore this email.

        Best regards,
        ConcealSafe Team
        """
        mail.send(msg)

        flash("We have sent a password reset link to your email. Please check your inbox.", "info")
        cur.close()
        con.close()
        return redirect(url_for("loginsafe"))
    else:
        # Redirect to signup if the account doesn't exist
        flash("No account found with this email. Please sign up.", "warning")
        cur.close()
        con.close()
        return redirect(url_for("signupsafe1"))



#**********************************************************#
#********************reset_password route*******************#
#**********************************************************#  
@app.route("/reset_password/<int:user_id>", methods=["GET", "POST"])
#Reset user password.
def reset_password(user_id):
    """Reset user password."""
    if request.method == "POST":
        user_id = request.form["user_id"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password", user_id=user_id))

        # Hash and update the password
        hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        con = mysql.connection
        cur = con.cursor()
        cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed_password, user_id))
        con.commit()
        cur.close()
        con.close()

        flash("Password has been updated successfully!", "success")
        return redirect(url_for("loginsafe"))

    return render_template("reset_password.html", user_id=user_id)


@app.route("/edit_password/<int:user_id>", methods=["GET", "POST"])
def edit_password(user_id):
    """Edit user password."""
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        # Validate the current password by checking it against the stored one
        con = mysql.connection
        cur = con.cursor()
        cur.execute("SELECT password FROM users WHERE user_id=%s", (user_id,))
        stored_password = cur.fetchone()

        if not stored_password or not bcrypt.checkpw(current_password.encode("utf-8"), stored_password[0].encode("utf-8")):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("edit_password", user_id=user_id))

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("edit_password", user_id=user_id))

        # Hash and update the new password
        hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed_password, user_id))
        con.commit()
        cur.close()
        con.close()

        flash("Password has been updated successfully!", "success")
        return redirect(url_for("viewprofile"))

    return render_template("edit_password.html", user_id=user_id)




#**********************************************************#
#**********************logout route************************#
#**********************************************************#    
@app.route("/logout")
def logout():
    """Handle user logout."""
    session.clear()  # Clear all session data
    flash('You have been logged out.', 'info')
    return redirect(url_for('loginsafe'))




# Run the application
if __name__ == '__main__':
    app.run(debug=True)

