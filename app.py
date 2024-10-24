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

mysql = MySQL()
app = Flask(__name__)

# Configure the secret key for session management
app.secret_key = 'g5$8^bG*dfK4&2e3yH!Q6j@z'  # Currently hard-coded, change when deploying

# Configure MySQL with Flask app 
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'root'
app.config['MYSQL_DATABASE_DB'] = 'concealsafe'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

# Set the timeout period in seconds (15 minutes)
SESSION_TIMEOUT = 900

def generate_keys_and_certificate(user_name):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user_name)
    ])
    
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).serial_number(
        x509.random_serial_number()
    ).public_key(public_key).sign(private_key, hashes.SHA256(), default_backend())
    
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    return private_key_bytes, certificate_bytes

def get_user_certificate(email):
    con = mysql.connect()
    cur = con.cursor()
    cur.execute("SELECT `certificate` FROM `users` WHERE `email` = %s", (email,))
    certificate = cur.fetchone()
    return certificate[0] if certificate else None

@app.before_request
def check_session_timeout():
    if 'last_activity' in session:
        elapsed_time = time.time() - session['last_activity']
        if elapsed_time > SESSION_TIMEOUT:
            session.clear()  # Clear the session
            flash('Session timed out. Please log in again.', 'warning')
            return redirect(url_for('loginsafe'))
    
    session['last_activity'] = time.time()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('loginsafe'))  # Redirect to login page if not logged in
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def homepage():
    return render_template('homepage.html')

@app.route("/userHomePage")
@login_required
def userHomePage():
     user_name = session.get('user_name')  # Get the user_name from the session
     return render_template('userHomePage.html', user_name=user_name)


@app.route("/signupsafe1", methods=['GET', 'POST'])
def signupsafe1():
    con = mysql.connect()
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
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store user details and certificate in the database
        cur.execute("INSERT INTO `users`(`user_name`, `email`, `password`, `certificate`) VALUES (%s, %s, %s, %s)",
                    (user_name, email, hashed_password.decode('utf-8'), certificate.decode()))
        con.commit()

        # Store private key in the session
        session['private_key'] = base64.b64encode(private_key).decode()
        session['user_id'] = cur.lastrowid  # Store user ID in session

        flash('Registration successful! Please check your email for confirmation.', 'success')  # Optional success message
        return render_template('registration_confirmation.html', user_name=user_name)

    cur.close()
    con.close()
    return render_template('signupsafe1.html')

@app.route("/download_private_key")
@login_required
def download_private_key():
    # Fetch the private key from the session
    private_key_b64 = session.get('private_key')

    if private_key_b64:
        # Decode the base64 encoded private key back to bytes
        private_key = base64.b64decode(private_key_b64)
        return send_file(
            io.BytesIO(private_key),
            as_attachment=True,
            attachment_filename='private_key.pem',
            mimetype='application/x-pem-file'
        )
    else:
        return "Private key not found", 404

@app.route("/ForgotPassword", methods=['GET', 'POST'])
def ForgotPassword():
    return render_template('ForgotPassword.html')

@app.route("/viewprofile")
@login_required
def viewprofile():
    return render_template('viewprofile.html')

@app.route("/messages")
@login_required
def messages():
    return render_template('messages.html')

@app.route("/decrypt")
@login_required
def decrypt():
    return render_template('decrypt.html')

@app.route("/encryptionPage")
@login_required
def encryptionPage():
    return render_template('encryptionPage.html')

@app.route("/loginsafe", methods=['GET', 'POST'])
def loginsafe():
    con = mysql.connect()
    cur = con.cursor()

    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        # Check if the user exists in the database
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if user:
            stored_hashed_password = user[3]  # Assuming the password is stored in the 3rd column (index 3)
            
            # Check if the hashed password matches the entered password
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                session['user_id'] = user[0]  # Store user ID in session
                session['user_name'] = user[1]  
                return redirect(url_for('userHomePage'))
            else:
                return render_template('loginsafe.html', error="Invalid email or password")
        else:
            return render_template('loginsafe.html', error="Invalid email or password")
    
    return render_template('loginsafe.html')  # Default page load

@app.route("/logout")
def logout():
    session.clear()  # Clear the session data
    flash('You have been logged out.', 'info')  # Optional flash message
    return redirect(url_for('homepage'))  # Redirect to home page after logout

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == "__main__":
    app.run(debug=True)
