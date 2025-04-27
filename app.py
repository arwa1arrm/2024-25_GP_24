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
            download_name='keys.zip',  # Updated this line
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
    con = get_db_connection()
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


#**************************************************************#
#**********************update_username route*******************#
#***************************************************************#

@app.route("/update_username", methods=["POST"])
@login_required
def update_username():
    """Handle updating the user's username."""
    user_id = session.get("user_id")  # Get the logged-in user's ID
    new_username = request.form.get("new_username")  # Fetch the new username from the form

    # Validate the input
    if not new_username or len(new_username) < 3:
        flash("Your name must be at least 3 characters long.", "warning")
        return redirect(url_for("viewprofile"))

    try:
        # Update the username in the database
        con = get_db_connection()
        cur = con.cursor()
        cur.execute("UPDATE users SET user_name=%s WHERE user_id=%s", (new_username, user_id))
        con.commit()
        
        # Check if the update was successful
        if cur.rowcount > 0:  # `rowcount` indicates the number of rows affected
            # Update the session with the new username
            session["user_name"] = new_username
            flash("Your name updated successfully!", "success")
        else:
            flash("No changes were made. Please try again.", "warning")
        
        cur.close()
        con.close()

    except Exception as e:
        # Handle database errors
        flash(f"An error occurred: {str(e)}. Please try again.", "danger")
        return redirect(url_for("viewprofile"))

    return redirect(url_for("viewprofile"))

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
    con = get_db_connection()
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

        con = get_db_connection()
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
        con = get_db_connection()
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


#************************************************************#
#************Steps before the encryption ********************#
#************************************************************#
#************************************************************#

# Ensure a temporary folder exists
UPLOAD_FOLDER = os.path.join(app.root_path, "uploads", "temp_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function: Encode a message with Zero-Width Characters
def encode_with_zero_width(message):
    """Encodes a binary message using Zero-Width Characters."""
    zero_width_mapping = {'0': '\u200b', '1': '\u200c'}
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    encoded_message = ''.join(zero_width_mapping[bit] for bit in binary_message)
    return encoded_message

# Utility functions for Zero-Width Encoding
def decode_with_zero_width(encoded_text):
    """Decodes a Zero-Width encoded message back to plaintext."""
    zero_width_mapping = {'\u200b': '0', '\u200c': '1'}
    binary_message = ''.join(zero_width_mapping[char] for char in encoded_text if char in zero_width_mapping)
    decoded_message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
    return decoded_message

import subprocess

def embed_message_in_metadata(video_path, encrypted_message, hidden_path):
    """Embed a hidden message into video metadata."""
    command = [
        "ffmpeg", "-i", video_path, "-c", "copy", 
        "-metadata", f"title={base64.b64encode(encrypted_message.encode()).decode()}", 
        hidden_path
    ]
    subprocess.run(command, check=True)
    return hidden_path


#************************************************************#
#*****************calculate_file_hash ***********************#
#************************************************************#
#********validate If any changes happened in the file********#
#************************************************************#

import hashlib

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

#**************************************************************#
#*************encrypt_and_hide route***************************#
#*****************************************************#

@app.route("/encrypt_and_hide", methods=["POST"])
@login_required
def encrypt_and_hide():
    sender_id = session.get('user_id')
    receiver_email = request.form.get("receiverEmail")
    plaintext_message = request.form.get("message")
    uploaded_file = request.files.get("mediaFile")

    # Basic validation
    if not receiver_email or not plaintext_message:
        flash("Receiver email and message are required.", "danger")
        return redirect(url_for("encryptionPage"))

    con = get_db_connection()
    cur = con.cursor()


    try:
        # Retrieve receiver details
        cur.execute("SELECT user_id, certificate FROM users WHERE email = %s", (receiver_email,))
        receiver_data = cur.fetchone()
        if not receiver_data:
            flash("The receiver's email is not registered.", "danger")
            return redirect(url_for("encryptionPage"))

        receiver_id, receiver_certificate_pem = receiver_data
        receiver_certificate = x509.load_pem_x509_certificate(receiver_certificate_pem.encode(), default_backend())
        receiver_public_key = receiver_certificate.public_key()


        # Retrieve sender details
        cur.execute("SELECT certificate FROM users WHERE user_id = %s", (sender_id,))
        sender_certificate_pem = cur.fetchone()[0]
        sender_certificate = x509.load_pem_x509_certificate(sender_certificate_pem.encode(), default_backend())
        sender_public_key = sender_certificate.public_key()

        # Step 1: Encrypt the message with AES symmetric encryption
        symmetric_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_message.encode()) + encryptor.finalize()
        # Prepend IV to ciphertext and base64 encode the result.
        encrypted_message = base64.b64encode(iv + ciphertext).decode()

        # Step 2: Encrypt the symmetric key using both receiver's and sender's public keys
        encrypted_key_receiver = base64.b64encode(receiver_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )).decode()

        encrypted_key_sender = base64.b64encode(sender_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )).decode()

        hidden_filename = None
        hidden_path = None

        # Step 3: Handle file embedding if a file is uploaded
        if uploaded_file and uploaded_file.filename:
            file_extension = os.path.splitext(uploaded_file.filename)[1].lower()
            allowed_extensions = [
                '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp',
                '.txt', '.docx', '.pdf', '.rtf',
                '.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a',
                '.mp4', '.avi', '.mkv', '.mov'
            ]
            if file_extension not in allowed_extensions:
                flash("Invalid file type. Please upload a supported media file.", "danger")
                return redirect(url_for("encryptionPage"))

            media_file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
            uploaded_file.save(media_file_path)


            

            # For capacity checking, create a binary version of the encrypted message.
            binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message) + '11111111'

            if file_extension == '.txt':
                with open(media_file_path, "r", encoding="utf-8") as text_file:
                    text_content = text_file.read()

               # Encode message using zero-width characters (this is a placeholder function)
                zero_width_message = encode_with_zero_width(encrypted_message)
                hidden_text_content = text_content + zero_width_message
                
                hidden_filename = f"hidden_{uploaded_file.filename}"
                hidden_path = os.path.join(UPLOAD_FOLDER, hidden_filename)
                with open(hidden_path, "w", encoding="utf-8") as hidden_file:
                    hidden_file.write(hidden_text_content)

            elif file_extension == '.pdf':
                from PyPDF2 import PdfReader, PdfWriter
                reader = PdfReader(media_file_path)
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                # For PDFs we embed the encrypted message in the metadata.
                writer.add_metadata({'/HiddenMessage': encrypted_message})
                hidden_filename = f"hidden_{uploaded_file.filename}"
                hidden_path = os.path.join(UPLOAD_FOLDER, hidden_filename)
                with open(hidden_path, "wb") as hidden_pdf:
                    writer.write(hidden_pdf)

            elif file_extension == '.docx':
                import docx
                doc = docx.Document(media_file_path)
                # Capacity is generally not an issue in DOCX, so we add the message as a hidden paragraph.
                para = doc.add_paragraph(encrypted_message)
                if para.runs:
                    para.runs[0].font.hidden = True
                hidden_filename = f"hidden_{uploaded_file.filename}"
                hidden_path = os.path.join(UPLOAD_FOLDER, hidden_filename)
                doc.save(hidden_path)

            # Audio Steganography
            elif file_extension in [".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"]:
                # Convert to WAV if needed so that we can work with wave module
                if file_extension != ".wav":
                    audio = AudioSegment.from_file(media_file_path)
                    wav_path = os.path.join(UPLOAD_FOLDER, "converted_temp.wav")
                    audio.export(wav_path, format="wav")
                else:
                    wav_path = media_file_path

                with wave.open(wav_path, "rb") as audio_file:
                    params = audio_file.getparams()
                    frames = bytearray(audio_file.readframes(audio_file.getnframes()))
                
                msg_idx = 0
                for i in range(len(frames)):
                    if msg_idx < len(binary_message):
                        frames[i] = (frames[i] & 0xFE) | int(binary_message[msg_idx])
                        msg_idx += 1
                    else:
                        break
                hidden_filename = f"hidden_{uploaded_file.filename}.wav"
                hidden_path = os.path.join(UPLOAD_FOLDER, hidden_filename)
                with wave.open(hidden_path, "wb") as hidden_audio_file:
                    hidden_audio_file.setparams(params)
                    hidden_audio_file.writeframes(frames)

            elif file_extension in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp']:
                from PIL import Image
                img = Image.open(media_file_path)
                encoded_img = img.copy()
                width, height = img.size
                max_capacity = width * height * 3  # Each pixel has 3 channels (RGB)
               # if len(binary_message) > max_capacity:
                #    flash("The selected image is too small to hide the message.", "danger")
                 #   return redirect(url_for("encryptionPage"))
                msg_idx = 0
                for x in range(width):
                    for y in range(height):
                        pixel = list(encoded_img.getpixel((x, y)))
                        for i in range(3):  # For R, G, B channels
                            if msg_idx < len(binary_message):
                                pixel[i] = (pixel[i] & ~1) | int(binary_message[msg_idx])
                                msg_idx += 1
                        encoded_img.putpixel((x, y), tuple(pixel))
                        if msg_idx >= len(binary_message):
                            break
                    if msg_idx >= len(binary_message):
                        break
                hidden_filename = f"hidden_{uploaded_file.filename}"
                hidden_path = os.path.join(UPLOAD_FOLDER, hidden_filename)
                encoded_img.save(hidden_path)

            elif file_extension == '.rtf':
                import striprtf
                with open(media_file_path, "r", encoding="utf-8") as rtf_file:
                    text_content = striprtf.rtf_to_text(rtf_file.read())
                hidden_text_content = f"{text_content}\n[HIDDEN MESSAGE]: {encrypted_message}"
                hidden_filename = f"hidden_{uploaded_file.filename}"
                hidden_path = os.path.join(UPLOAD_FOLDER, hidden_filename)
                with open(hidden_path, "w", encoding="utf-8") as hidden_file:
                    hidden_file.write(hidden_text_content)

            # For video files, embed the message in the metadata
            elif file_extension in ['.mp4', '.avi', '.mkv', '.mov']:
                hidden_filename = f"hidden_{uploaded_file.filename}"
                hidden_path = os.path.join(UPLOAD_FOLDER, hidden_filename)
                # Embed the encrypted message in video metadata
                hidden_path = embed_message_in_metadata(media_file_path, encrypted_message, hidden_path)
        # Calculate the file hash if a hidden file was created
        file_hash = calculate_file_hash(hidden_path) if hidden_path else None

        # Save the encrypted message and keys into the database
        cur.execute("""
            INSERT INTO message 
            (EncryptedSharedKeyReceiver, EncryptedSharedKeySender, Content, MediaFile, SenderID, RecipientID, Filename, FileHash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            encrypted_key_receiver,
            encrypted_key_sender,
            encrypted_message,
            hidden_filename,
            sender_id,
            receiver_id,
            hidden_filename,
            file_hash
        ))
        con.commit()

        flash("Message encrypted, hidden, and sent successfully.", "success")
        if hidden_filename:
            download_url = url_for("download_file", filename=hidden_filename, _external=True)
            return render_template("encryptionPage.html", download_url=download_url, filename=hidden_filename)
        else:
            return render_template("encryptionPage.html")

    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        con.rollback()
        return redirect(url_for("encryptionPage"))
    finally:
        cur.close()
        con.close()


#**************************************************************#
#**********************sent_message route***********************#
#***************************************************************#
@app.route("/sent_messages", methods=["GET", "POST"])
@login_required
def sent_messages():
    """Display the messages sent by the user with sorting and delete option."""
    sender_id = session.get("user_id")  # Get the logged-in user's ID
    search_email = request.form.get("search_email", "").strip()
    sort_by = request.args.get("sort_by", "date_desc")  # Default sorting by date descending

    con = get_db_connection()
    cur = con.cursor()


    # Base query
    query = """
    SELECT 
        m.MessageID,
        m.Content AS EncryptedMessage,
        u.email AS ReceiverEmail,
        m.Filename,
        m.sent_date,
        m.IsRead  -- Make sure you include IsRead here
    FROM 
        message m
    JOIN 
        users u 
    ON 
        m.RecipientID = u.user_id
    WHERE 
        m.SenderID = %s
    """
    

    params = [sender_id]

    # Search filter
    if search_email:
        query += " AND u.email LIKE %s"
        params.append(f"%{search_email}%")

    # Sorting logic
    sort_column = "m.sent_date"
    sort_order = "DESC" if sort_by == "date_desc" else "ASC"

    if sort_by == "name_asc":
        sort_column, sort_order = "u.email", "ASC"
    elif sort_by == "name_desc":
        sort_column, sort_order = "u.email", "DESC"
    elif sort_by == "status_asc":
        sort_column, sort_order = "m.IsRead", "ASC"  # Unread first
    elif sort_by == "status_desc":
        sort_column, sort_order = "m.IsRead", "DESC"  # Read first

    query += f" ORDER BY {sort_column} {sort_order}"

    cur.execute(query, params)
    messages = cur.fetchall()

    messages_list = [
        {
            "MessageID": message[0],
            "EncryptedMessage": message[1],
            "ReceiverEmail": message[2],
            "Filename": message[3],
            "SentDate": message[4].strftime("%Y-%m-%d %H:%M:%S") if message[4] else None,
            "IsRead": message[5]  # Add this line to include the "IsRead" status

        }
        for message in messages
    ]

    cur.close()
    con.close()

    return render_template("sent_messages.html", messages=messages_list, search_email=search_email, sort_by=sort_by)

#****************************************************#
#******* delete_message route for sent messages *****#
#****************************************************#
@app.route("/delete_message/<int:message_id>", methods=["GET"])
@login_required
def delete_message(message_id):
    """Delete a sent message."""
    sender_id = session.get("user_id")
    
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("DELETE FROM message WHERE MessageID = %s AND SenderID = %s", (message_id, sender_id))
    con.commit()
    cur.close()
    con.close()
    
    flash("Message deleted successfully", "success")
    return redirect(url_for("sent_messages"))

#****************************************************#
#******* delete_message route for messages **********#
#****************************************************#

@app.route("/delete_message_rec/<int:message_id>", methods=["GET"])
@login_required
def delete_message_rec(message_id):
    """Delete a sent message."""
    sender_id = session.get("user_id")
    
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("DELETE FROM message WHERE MessageID = %s AND SenderID = %s", (message_id, sender_id))
    con.commit()
    cur.close()
    con.close()
    
    flash("Message deleted successfully", "success")
    return redirect(url_for("messages"))

#**************************************************************#
#****************get_unread_messages route*********************#
#**************************************************************#
@app.route('/get_unread_messages_count')
@login_required
def get_unread_messages_count():
    user_id = session.get("user_id")  

    con = get_db_connection()
    cur = con.cursor()

    # Query to count unread messages
    query = """
    SELECT COUNT(*) 
    FROM message 
    WHERE RecipientID = %s AND IsRead = 0
    """
    cur.execute(query, (user_id,))
    if result:
        unread_count = result[0]   
    else:
        unread_count = 0  
    cur.close()
    con.close()

    return jsonify({"unread_count": unread_count})

#**************************************************************#
#**********************messages route**************************#
#***************************************************************#
@app.route('/messages', methods=["GET", "POST"])
@login_required
def messages():
    user_id = session.get('user_id')  
    search_email = request.form.get("search_email", "").strip()
    sort_by = request.args.get("sort_by", "date_desc")

    con = get_db_connection()
    cur = con.cursor()

    # Base query
    query = """
    SELECT 
        m.MessageID,
        m.EncryptedSharedKeyReceiver,
        m.Content AS EncryptedMessage,
        u.email AS SenderEmail,
        m.Filename,
        m.sent_date,
        m.IsRead
    FROM 
        message m
    JOIN 
        users u 
    ON 
        m.SenderID = u.user_id
    WHERE 
        m.RecipientID = %s
    """
    params = [user_id]

    # Add search filter correctly
    if search_email:
        query += " AND u.email LIKE %s"
        params.append(f"%{search_email}%")

    # Sorting logic
    sort_column = "m.sent_date"
    sort_order = "DESC" if sort_by == "date_desc" else "ASC"

    if sort_by == "name_asc":
        sort_column, sort_order = "u.email", "ASC"
    elif sort_by == "name_desc":
        sort_column, sort_order = "u.email", "DESC"
    elif sort_by == "status_asc":
        sort_column, sort_order = "m.IsRead", "ASC"
    elif sort_by == "status_desc":
        sort_column, sort_order = "m.IsRead", "DESC"

    # Append ORDER BY once
    query += f" ORDER BY {sort_column} {sort_order}"

    # Execute query
    cur.execute(query, params)
    messages = cur.fetchall()

    # Convert results to a list of dictionaries for the template
    messages_list = [
        {
            "MessageID": message[0],
            "EncryptedSharedKeyReceiver": message[1],
            "EncryptedMessage": message[2],
            "SenderEmail": message[3],
            "Filename": message[4],
            "SentDate": message[5].strftime("%Y-%m-%d %H:%M:%S") if message[5] else None,
            "IsRead": message[6]
        }
        for message in messages
    ]

    cur.close()
    con.close()

    return render_template('messages.html', messages=messages_list, search_email=search_email, sort_by=sort_by)



#**************************************************************#
#**********************download route***************************#
#**************************************************************#
@app.route("/download_file/<filename>")
@login_required
def download_file(filename):
    """Handle downloading hidden media files."""
    uploads_dir = os.path.join(app.root_path, "uploads", "temp_files")  # Ensure the directory path is correct
    try:
        return send_from_directory(uploads_dir, filename, as_attachment=True)
    except FileNotFoundError:
        flash("File not found on the server.", "danger")
        return redirect(url_for("encryptionPage"))

#**************************************************************#
#**********************decrypt route***************************#
#**************************************************************#

def get_file_extension(filename):
    """Extract the file extension from the filename."""
    return os.path.splitext(filename)[1].lower()

def extract_message_from_metadata(video_path):
    """Extract a hidden message from video metadata."""
    command = ["ffprobe", "-v", "quiet", "-show_entries", "format_tags=title", "-of", "default=noprint_wrappers=1:nokey=1", video_path]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    
    extracted_message = result.stdout.strip()
    
    # DEBUGGING: Print extracted message
    print(f"Extracted metadata message: {extracted_message}")

    try:
        # Base64 decode before returning
        decoded_message = base64.b64decode(extracted_message).decode('utf-8')
        return decoded_message
    except Exception as e:
        print(f"Decoding failed: {e}")  # Print if decoding fails
        return extracted_message  # If decoding fails, return raw message


@app.route("/extract_and_decrypt", methods=["POST"])
@login_required
def extract_and_decrypt():
    # Retrieve the message ID and uploaded private key file
    message_id = request.form.get("message_id")
    private_key_file = request.files.get("privateKey")  # Access the uploaded private key file

    # Validate that the required inputs are provided
    if not message_id or not private_key_file or private_key_file.filename == '':
        flash("Message ID and private key file are required.", "danger")
        return redirect(url_for("decrypt", message_id=message_id))

    temp_file_path = None

    try:
        # Read and decode the private key from the uploaded file
        private_key_data = private_key_file.read().decode('utf-8')

        # Validate that the private key data is not empty
        if not private_key_data.strip():
            flash("The private key file is empty. Please upload a valid private key.", "danger")
            return redirect(url_for("decrypt", message_id=message_id))

        # Fetch the filename, encrypted shared key, and encrypted message from the database
        con = get_db_connection()
        cur = con.cursor()

        cur.execute("SELECT Filename, EncryptedSharedKeyReceiver, Content FROM message WHERE MessageID = %s", (message_id,))
        result = cur.fetchone()
        cur.close()
        con.close()

        if not result:
            flash("Message not found in the database.", "danger")
            return redirect(url_for("decrypt", message_id=message_id))

        expected_filename, encrypted_shared_key, encrypted_message = result

        # Decrypt the symmetric key using the provided private key
        private_key = serialization.load_pem_private_key(
            private_key_data.encode(),  # Convert string to bytes
            password=None,  # Assumes no password protection
            backend=default_backend()
        )
        symmetric_key = private_key.decrypt(
            base64.b64decode(encrypted_shared_key),  # Decode the base64-encoded shared key
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the encrypted message using the symmetric key
        cipher_text_bytes = base64.b64decode(encrypted_message)
        iv, ciphertext = cipher_text_bytes[:16], cipher_text_bytes[16:]  # Extract the IV and ciphertext
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        plaintext_message = decryptor.update(ciphertext) + decryptor.finalize()

        # *** Mark the message as read (seen) in the database ***
        con = get_db_connection()
        cur = con.cursor()
        cur.execute("UPDATE message SET IsRead = 1 WHERE MessageID = %s", (message_id,))
        con.commit()
        cur.close()
        con.close()
        # **********************************************

        # Display the decrypted message to the user
        flash("Message decrypted successfully.", "success")
        return render_template(
            "decrypt.html",
            plaintext_message=plaintext_message.decode(),  # Pass the decrypted message
            encrypted_message=encrypted_message,
            message_id=message_id
        )

    except Exception as e:
        # Handle exceptions and provide feedback to the user
        flash(f"An error occurred during decryption: {str(e)}", "danger")
        return redirect(url_for("decrypt", message_id=message_id))

    finally:
        # Clean up temporary files if any were created
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)




#**************************************************************#
#**********************decrypt page route**********************#
#**************************************************************#
@app.route("/decrypt", methods=["GET"])
@login_required
def decrypt():
    message_id = request.args.get("message_id")

    if not message_id:
        flash("No message selected for decryption.", "danger")
        return redirect(url_for("sent_messages"))

    # Pass the message_id to the template for use in decryption
    return render_template("decrypt.html", message_id=message_id)



#**************************************************************#
#**********************encrypttionpage route****************************#
#***************************************************************#

@app.route("/encryptionPage", methods=['GET', 'POST'])
@login_required
# Render the encryption page and handle message encryption
def encryptionPage():
    sender_id = session.get('user_id')  
    key = session.get('symmetric_key')  # Retrieve the symmetric key from the session (or generate it if not available)

    if request.method == 'POST':
        message = request.form['message']  # Message to be sent
        recipient_email = request.form['email']  # Email of the recipient


        # Retrieve the recipient's user ID from the database
        con = get_db_connection()
        cur = con.cursor()

        cur.execute("SELECT user_id, certificate FROM users WHERE email = %s", (recipient_email,))
        recipient_data = cur.fetchone()
        cur.close()
        con.close()

        if recipient_data:
            recipient_id = recipient_data[0]  # Get recipient's user ID
            recipient_public_key = recipient_data[4]  


            # Encrypt the message using the symmetric key
            encrypted_message = encrypt_message(message, key)

            # Encrypt the symmetric key using the recipient's public key
            encrypted_symmetric_key = encrypt_with_public_key(key, recipient_public_key)

            # Store the encrypted message in the database
            con = get_db_connection()
            cur = con.cursor()
            cur.execute(
                "INSERT INTO message (EncryptedSharedKey, Content, SenderID, RecipientID) VALUES (%s, %s, %s, %s)",
                (encrypted_symmetric_key, encrypted_message, sender_id, recipient_id)
            )
            con.commit()
            cur.close()
            con.close()

            flash('Message sent successfully!', 'success')
            return redirect(url_for('userHomePage')) 
        else:
            flash('Recipient not found. Please check the email.', 'danger')

    return render_template('encryptionPage.html') 
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

