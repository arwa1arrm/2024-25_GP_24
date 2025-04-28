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
from flask_session import Session
import redis


def parse_database_url(url):
    result = urlparse(url)
    return result.username, result.password, result.hostname, result.path[1:]


# Initialize Flask app  and MySQL
app = Flask(__name__)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)  #
#Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False  
app.config['SESSION_USE_SIGNER'] = True 
app.config['SESSION_KEY_PREFIX'] = 'concealsafe_'  
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'g5$8^bG*dfK4&2e3yH!Q6j@z')

app.config['SESSION_REDIS'] = redis.from_url(os.getenv('UPSTASH_REDIS_URL'))

# 
Session(app)


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
# Set the timeout period in seconds (15 minutes)
SESSION_TIMEOUT = 900



#**************************************************************#
#*********************CERTIFICATE GENERATION*******************#
#**************************************************************#

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import *
from cryptography.hazmat.backends import default_backend
import datetime

def generate_keys_and_certificate(user_name):
    """Generate RSA keys and self-signed certificate for the user."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # commonly used
        key_size=2048,  # considered safe
        backend=default_backend()
    )
    
    public_key = private_key.public_key()  # Public Key Extraction
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, user_name)])  # Certificate Subject and Issuer
    
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).serial_number(
        x509.random_serial_number()  # Assigns a unique serial number to the certificate
    ).public_key(public_key).sign(private_key, hashes.SHA256(), default_backend())  # Adds the public key to the certificate and signs it using the SHA-256 hashing algorithm with the private key
    
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Converts the private key into a byte format (PEM), which can be easily saved or transmitted.
    )
    
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)  # Similarly, converts the certificate into PEM-encoded bytes

    return private_key_bytes, certificate_bytes

def load_private_key(pem_data):
    try:
        # Load the private key from PEM data
        private_key = serialization.load_pem_private_key(
            pem_data,  # Ensure it's already in bytes, no need to encode
            password=None,  # If the private key is not password-protected
            backend=default_backend()  # Use the default backend for cryptography
        )
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

def load_certificate(cert_pem_data):
    try:
        # Load the certificate from PEM data
        certificate = x509.load_pem_x509_certificate(cert_pem_data, default_backend())
        return certificate
    except Exception as e:
        print(f"Error loading certificate: {e}")
        return None

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
#*****************download_private_key route****************#
#**********************************************************#

@app.route("/download_keys_zip")
@login_required
def download_keys_zip():
    """Allow users to download both their private key and certificate in a zip file."""

    # Retrieve the private key and certificate from session
    private_key_b64 = session.get('private_key')
    
    certificate = session.get('certificate')

    # Check if both the private key and certificate are available in session
    if private_key_b64 and certificate:
        try:
            # Decode the private key from base64
            private_key = base64.b64decode(private_key_b64)
            
            # Verify the private key and certificate format if necessary
            if not private_key.startswith(b'-----BEGIN PRIVATE KEY-----') or not private_key.endswith(b'-----END PRIVATE KEY-----'):
                flash("Error: The private key is not in the correct PEM format.", "danger")
                return redirect(url_for('userHomePage'))

            if not certificate.startswith(b'-----BEGIN CERTIFICATE-----') or not certificate.endswith(b'-----END CERTIFICATE-----'):
                flash("Error: The certificate is not in the correct PEM format.", "danger")
                return redirect(url_for('userHomePage'))

            # Create a ZIP file in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add private key to zip
                zip_file.writestr('private_key.pem', private_key)
                # Add certificate (public key) to zip
                zip_file.writestr('public_key.pem', certificate)

            zip_buffer.seek(0)  # Reset pointer to the start of the zip buffer

            # Send the zip file to the user
            return send_file(
                zip_buffer,
                as_attachment=True,
                download_name='keys.zip',  # Use download_name instead of attachment_filename
                mimetype='application/zip'
            )

        except Exception as e:
            # Catch any errors during the process
            flash(f"An error occurred while preparing your download: {str(e)}", "danger")
            return redirect(url_for('userHomePage'))

    else:
        flash('One or both keys are not found in your session. Please register again or contact support.', 'danger')
        return redirect(url_for('userHomePage'))



#**********************************************************#
#**********************Signup route************************#
#**********************************************************#
@app.route("/signupsafe1", methods=['GET', 'POST'])
#Handle user resistration
def signupsafe1():
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
            return render_template('signupsafe1.html', error="Email is already registered!")

        # Generate keys and certificate
        private_key, certificate = generate_keys_and_certificate(user_name)

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) #Many hashing algorithms, including bcrypt, require the input to be in byte format, so encoding is necessary.


        # Store private key in the session
        session['private_key'] = base64.b64encode(private_key).decode()
        session['user_id'] = cur.lastrowid  # Store user ID in session
        
        # Store user details in session instead of the database
        session['user_name'] = user_name
        session['email'] = email
        session['password'] = password
        session['certificate'] = base64.b64encode(certificate).decode('utf-8')

        
        # Generate and send OTP
        otp = generate_otp()
        session['otp'] = otp  # Store OTP in session
        session['email'] = email  # Store email in session
        send_otp_email(email, otp)  # Your function to send OTP

        flash('OTP has been sent to your email. Please verify to complete registration.', 'info')
        return redirect(url_for('verify_otp'))

    cur.close()
    con.close()
    return render_template('signupsafe1.html')


#**********************************************************#
#**********************verify_otp route*******************#
#**********************************************************#    
# Constants
MAX_OTP_ATTEMPTS = 3
INITIAL_COOLDOWN_PERIOD = 1 
COOLDOWN_INCREMENT = 2       

@app.route("/verify_otp", methods=["GET", "POST"])
#Hnadle OTP verification for registration
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
            con = get_db_connection()
            cur = con.cursor()

            # Hash the password
            hashed_password = bcrypt.hashpw(session['password'].encode('utf-8'), bcrypt.gensalt())

            # Insert the user data into the database
            cur.execute("INSERT INTO `users`(`user_name`, `email`, `password`, `certificate`) VALUES (%s, %s, %s, %s)",
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





# Run the application
if __name__ == '__main__':
    app.run(debug=True)