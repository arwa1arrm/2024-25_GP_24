import re
import time
from flask import Flask, render_template, session, url_for, request, redirect, send_file, flash
from flaskext.mysql import MySQL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import io
import base64
import bcrypt
from functools import wraps

mysql = MySQL()  # Create a MySQL instance
app = Flask(__name__)  # Initialize the Flask app

# Configure the secret key for session management
app.secret_key = 'g5$8^bG*dfK4&2e3yH!Q6j@z'  # Hard-coded for now; change it for production

# Set up MySQL database connection details
app.config['MYSQL_DATABASE_USER'] = 'root'  # MySQL username
app.config['MYSQL_DATABASE_PASSWORD'] = 'root'  # MySQL password
app.config['MYSQL_DATABASE_DB'] = 'concealsafe'  # Database name
app.config['MYSQL_DATABASE_HOST'] = 'localhost'  # Database host
mysql.init_app(app)  # Initialize MySQL with Flask app

# Set session timeout to 15 minutes (900 seconds)
SESSION_TIMEOUT = 900

def generate_keys_and_certificate(user_name):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()  # Get the corresponding public key

    # Create subject and issuer for the certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user_name)
    ])
    
    # Build the certificate with expiration and signature
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).not_valid_before(
        datetime.datetime.utcnow()  # Certificate starts now
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)  # Valid for 1 year
    ).serial_number(
        x509.random_serial_number()  # Unique serial number
    ).public_key(public_key).sign(private_key, hashes.SHA256(), default_backend())
    
    # Convert private key to bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # No encryption for now
    )
    
    # Convert certificate to bytes
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    return private_key_bytes, certificate_bytes  # Return both keys

def get_user_certificate(email):
    # Connect to the database
    con = mysql.connect()
    cur = con.cursor()
    # Fetch the certificate for the given email
    cur.execute("SELECT `certificate` FROM `users` WHERE `email` = %s", (email,))
    certificate = cur.fetchone()  # Get the result
    return certificate[0] if certificate else None  # Return certificate or None

@app.before_request
def check_session_timeout():
    # Check if the user has a session activity time
    if 'last_activity' in session:
        elapsed_time = time.time() - session['last_activity']  # Calculate elapsed time
        if elapsed_time > SESSION_TIMEOUT:
            session.clear()  # Clear the session if timed out
            flash('Session timed out. Please log in again.', 'warning')  # Show warning message
            return redirect(url_for('loginsafe'))  # Redirect to login page
    
    session['last_activity'] = time.time()  # Update last activity time

def login_required(f):
    # Decorator to check if user is logged in
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # If user is not logged in
            return redirect(url_for('loginsafe'))  # Redirect to login page
        return f(*args, **kwargs)  # If logged in, run the original function
    return decorated_function

@app.route("/")  # Home page route
def homepage():
    return render_template('homepage.html')  # Render homepage template

@app.route("/userHomePage")  # User home page route
@login_required  # Require login for this page
def userHomePage():
    user_name = session.get('user_name')  # Get the user name from the session
    return render_template('userHomePage.html', user_name=user_name)  # Render user home page

@app.route("/signupsafe1", methods=['GET', 'POST'])  # Signup route
def signupsafe1():
    con = mysql.connect()  # Connect to the database
    cur = con.cursor()

    if request.method == "POST":  # If the form is submitted
        user_name = request.form['user_name']  # Get user name from form
        email = request.form['email']  # Get email from form
        password = request.form['password']  # Get password from form
        confirmPassword = request.form['confirmPassword']  # Get confirm password

        # Check if the email already exists in the DB
        cur.execute("SELECT email FROM users WHERE email=%s", (email,))
        existing_user = cur.fetchone()  # Check for existing user

        if existing_user:
            return render_template('signupsafe1.html', error="Email is already registered!")  # Show error if exists

        # Generate keys and certificate for the new user
        private_key, certificate = generate_keys_and_certificate(user_name)

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store user details and certificate in the database
        cur.execute("INSERT INTO `users`(`user_name`, `email`, `password`, `certificate`) VALUES (%s, %s, %s, %s)",
                    (user_name, email, hashed_password.decode('utf-8'), certificate.decode()))
        con.commit()  # Save changes to the database

        # Store private key in the session
        session['private_key'] = base64.b64encode(private_key).decode()  # Encode private key in base64
        session['user_id'] = cur.lastrowid  # Store user ID in session

        flash('Registration successful! Please check your email for confirmation.', 'success')  # Success message
        return render_template('registration_confirmation.html', user_name=user_name)  # Show confirmation page

    cur.close()  # Close the cursor
    con.close()  # Close the connection
    return render_template('signupsafe1.html')  # Render signup form

@app.route("/download_private_key")  # Download private key route
@login_required  # Require login for this page
def download_private_key():
    # Fetch the private key from the session
    private_key_b64 = session.get('private_key')  # Get private key from session

    if private_key_b64:
        # Decode the base64 encoded private key back to bytes
        private_key = base64.b64decode(private_key_b64)
        return send_file(
            io.BytesIO(private_key),  # Convert bytes to a stream
            as_attachment=True,  # Download as attachment
            attachment_filename='private_key.pem',  # Filename for download
            mimetype='application/x-pem-file'  # MIME type for PEM files
        )
    else:
        return "Private key not found", 404  # Return error if not found

@app.route("/ForgotPassword", methods=['GET', 'POST'])  # Forgot password route
def ForgotPassword():
    return render_template('ForgotPassword.html')  # Render forgot password page

@app.route("/viewprofile")  # View profile route
@login_required  # Require login for this page
def viewprofile():
    return render_template('viewprofile.html')  # Render profile page

@app.route("/messages")  # Messages route
@login_required  # Require login for this page
def messages():
    return render_template('messages.html')  # Render messages page

@app.route("/decrypt")  # Decrypt route
@login_required  # Require login for this page
def decrypt():
    return render_template('decrypt.html')  # Render decrypt page

@app.route("/encryptionPage")  # Encryption page route
@login_required  # Require login for this page
def encryptionPage():
    return render_template('encryptionPage.html')  # Render encryption page

@app.route("/loginsafe", methods=['GET', 'POST'])  # Login route
def loginsafe():
    con = mysql.connect()  # Connect to the database
    cur = con.cursor()

    if request.method == "POST":  # If the form is submitted
        email = request.form['email']  # Get email from form
        password = request.form['password']  # Get password from form

        # Check if the user exists in the database
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()  # Get user details

        if user:
            stored_hashed_password = user[3]  # Get stored hashed password
            
            # Check if the hashed password matches the entered password
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                session['user_id'] = user[0]  # Store user ID in session
                session['user_name'] = user[1]  # Store user name in session
                return redirect(url_for('userHomePage'))  # Redirect to user home page
            else:
                return render_template('loginsafe.html', error="Invalid email or password")  # Show error
        else:
            return render_template('loginsafe.html', error="Invalid email or password")  # Show error if user not found
    
    return render_template('loginsafe.html')  # Default page load for login

@app.route("/logout")  # Logout route
def logout():
    session.clear()  # Clear the session data
    flash('You have been logged out.', 'info')  # Show logout message
    return redirect(url_for('homepage'))  # Redirect to home page after logout

@app.after_request
def add_header(response):
    # Set headers to prevent caching
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response  # Return the response with added headers

if __name__ == "__main__":
    app.run(debug=True)  # Run the app in debug mode
