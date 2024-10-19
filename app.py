#this is app.py

import re
from flask import Flask, render_template, session, url_for, request, redirect, send_file
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

mysql = MySQL()
app = Flask(__name__)

# Configure the secret key for session management
app.secret_key = 'your_secret_key_here'  # Change this to a strong secret key!

# Configure MySQL with Flask app 
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'root'
app.config['MYSQL_DATABASE_DB'] = 'concealsafe'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

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

@app.route("/")
def homepage():
    return render_template('homepage.html')

@app.route("/userHomePage")
def userHomePage():
    return render_template('userHomePage.html')

@app.route("/signupsafe1", methods=['GET', 'POST'])
def signupsafe1():
    con = mysql.connect()
    cur = con.cursor()

    if request.method == "POST":
        user_name = request.form['user_name']
        email = request.form['email']
        password = request.form['password']
        confirmPassword = request.form['confirmPassword']  # Confirm password

        # Email format validation
        email_pattern = r'^[\w._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]'
        if not re.match(email_pattern, email):
            return render_template('signupsafe1.html', error="Invalid email format. Please enter a valid email (e.g., user@domain.com).")

        # Password length validation
        if len(password) < 8:
            return render_template('signupsafe1.html', error="Password must be at least 8 characters long.")
        
        # Password matching validation
        if password != confirmPassword:
            return render_template('signupsafe1.html', error="Confirm passwords do not match the entered password.")

        # Check if the email already exists in the DB
        cur.execute("SELECT email FROM users WHERE email=%s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            return render_template('signupsafe1.html', error="Email already registered!")

        # Generate keys and certificate
        private_key, certificate = generate_keys_and_certificate(user_name)

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store user details and certificate in the database (NOT storing private key)
        cur.execute("INSERT INTO `users`(`user_name`, `email`, `password`, `certificate`) VALUES (%s, %s, %s, %s)",
                    (user_name, email, hashed_password.decode('utf-8'), certificate.decode()))
        con.commit()

        # Store private key in the session
        session['private_key'] = base64.b64encode(private_key).decode()

        # Render the confirmation page after successful registration
        return render_template('registration_confirmation.html', user_name=user_name)

    # Close connection after handling request
    cur.close()
    con.close()

    return render_template('signupsafe1.html')

@app.route("/download_private_key")
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
def viewprofile():
    return render_template('viewprofile.html')

@app.route("/messages")
def messages():
    return render_template('messages.html')

@app.route("/decrypt")
def decrypt():
    return render_template('decrypt.html')

@app.route("/encryptionPage")
def encryptionPage():
    return render_template('encryptionPage.html')

@app.route("/loginsafe", methods=['GET', 'POST'])
def loginsafe():
    # connection
    con = mysql.connect()
    cur = con.cursor()

    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        # Check if the user exists in the database
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if user:
            stored_hashed_password = user[3]  # Assuming the password is stored in the 3rd column (index 2)
            
            # Check if the hashed password matches the entered password
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                # If password matches, redirect to user homepage
                return redirect(url_for('userHomePage'))
            else:
                # If password is incorrect, return error message
                return render_template('loginsafe.html', error="Invalid email or password")
        else:
            # If user doesn't exist, return error message
            return render_template('loginsafe.html', error="Invalid email or password")
    
    return render_template('loginsafe.html')  # default page load

@app.route("/send_message", methods=['POST'])
def send_message():
    sender_email = request.form['sender_email']
    recipient_email = request.form['recipient_email']
    message = request.form['message']

    # Check if recipient email is provided
    if not recipient_email:
        return "Recipient email is required.", 400

    # Retrieve recipient's certificate
    recipient_certificate = get_user_certificate(recipient_email)

    if not recipient_certificate:
        return "Recipient not found.", 404

    # Implement your encryption logic here using the retrieved certificate

    return "Message sent successfully."

if __name__ == "__main__":
    app.run(debug=True)
