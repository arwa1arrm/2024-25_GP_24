import re  # Regular expressions
import time
import zipfile
from flask import Flask, render_template, session, url_for, request, redirect, send_file, flash, jsonify
from flaskext.mysql import MySQL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

import datetime  # For datetime.datetime.utcnow()
from datetime import timedelta  # For timedelta
import io
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


# Initialize Flask app and MySQL
app = Flask(__name__)
mysql = MySQL()

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



# Configure MySQL with Flask app 
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'root'
app.config['MYSQL_DATABASE_DB'] = 'concealsafe'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

# Set the timeout period in seconds (15 minutes)
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
    
    con = mysql.connect()
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
        con = mysql.connect()
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


#**************************************************************#
#**********************send_message route***********************#
#***************************************************************#
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    sender_email = session.get('user_email')
    receiver_email = request.form['receiver_email']
    plaintext_message = request.form['message']

    # Validate the receiver's email and get recipient user_id
    con = mysql.connect()
    cur = con.cursor()
    cur.execute("SELECT user_id, certificate FROM users WHERE email = %s", (receiver_email,))
    receiver = cur.fetchone()

    if not receiver:
        flash('The receiver\'s email is not registered.', 'error')
        return redirect(url_for('send_message_page'))

    receiver_id, receiver_certificate = receiver

    # Get sender's certificate from the session or database (you should have this available)
    cur.execute("SELECT certificate FROM users WHERE email = %s", (sender_email,))
    sender_certificate = cur.fetchone()[0]

    # Generate symmetric key for encryption
    symmetric_key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = base64.b64encode(iv + encryptor.update(plaintext_message.encode()) + encryptor.finalize()).decode()

    # Encrypt the symmetric key twice: once with receiver's public key and once with sender's public key
    receiver_public_key = serialization.load_pem_public_key(receiver_certificate.encode())
    encrypted_symmetric_key_receiver = base64.b64encode(receiver_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )).decode()

    # Encrypt with sender's public key as well
    sender_public_key = serialization.load_pem_public_key(sender_certificate.encode())
    encrypted_symmetric_key_sender = base64.b64encode(sender_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )).decode()

    # Get next MessageID
    cur.execute("SELECT MAX(MessageID) FROM message")
    next_message_id = (cur.fetchone()[0] or 0) + 1

    # Ensure the encrypted symmetric key length is within database constraints
    if len(encrypted_symmetric_key_receiver) > 255 or len(encrypted_symmetric_key_sender) > 255:
        flash('Encryption error: shared key too large for database storage.', 'error')
        return redirect(url_for('send_message_page'))

    # Store both encrypted symmetric keys and the message content in the database
    try:
        cur.execute("""
            INSERT INTO message (MessageID, EncryptedSharedKeyReceiver, EncryptedSharedKeySender, Content, SenderID, RecipientID)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (next_message_id, encrypted_symmetric_key_receiver, encrypted_symmetric_key_sender, encrypted_message, sender_email, receiver_id))
        con.commit()

        

        flash('Message sent successfully!', 'success')
    except Exception as e:
        con.rollback()
        flash(f'Error sending message: {e}', 'error')

    cur.close()
    return redirect(url_for('userHomePage'))




#**************************************************************#
#**********************sent_message route***********************#
#***************************************************************#
@app.route("/sent_messages", methods=["GET"])
@login_required
 #  Display the messages sent by the user.
def sent_messages():
    sender_id = session.get('user_id')

    con = mysql.connect()
    cur = con.cursor()
    cur.execute( """
    SELECT 
        m.MessageID,  -- Include MessageID
        m.EncryptedSharedKeySender, 
        m.Content AS EncryptedMessage, 
        u.email AS ReceiverEmail
    FROM 
        message m
    JOIN 
        users u 
    ON 
        m.RecipientID = u.user_id
    WHERE 
        m.SenderID = %s
""", (sender_id,))
   
    messages = cur.fetchall()
    # Convert to a list of dictionaries for easier template rendering
    messages_list = [
        {      
        "MessageID": message[0],
        "EncryptedSharedKeySender": message[1],
        "EncryptedMessage": message[2],
        "ReceiverEmail": message[3]
        }
        for message in messages
    ]

    cur.close()
    con.close()
    return render_template('sent_messages.html', messages=messages_list)


#**************************************************************#
#**********************messages route**************************#
#***************************************************************#
@app.route('/messages')
@login_required
def messages():
    user_id = session.get('user_id')  # Assuming user_id is stored in the session
    con = mysql.connect()
    cur = con.cursor()

    # Query to fetch messages where the user is the recipient
    cur.execute("""
    SELECT 
        m.MessageID,  -- Include MessageID
        m.EncryptedSharedKeyReceiver, 
        m.Content AS EncryptedMessage, 
        u.email AS SenderEmail
    FROM 
        message m
    JOIN 
        users u 
    ON 
        m.SenderID = u.user_id
    WHERE 
        m.RecipientID = %s
""", (user_id,))

    messages = cur.fetchall()  # Retrieve all messages
   
    # Convert to a list of dictionaries for easier template rendering
    messages_list = [
        {      
        "MessageID": message[0],
        "EncryptedSharedKeyReceiver": message[1],
        "EncryptedMessage": message[2],
        "SenderEmail": message[3]
        }
        for message in messages
    ]

    cur.close()
    con.close()
    return render_template('messages.html', messages=messages_list)

#**************************************************************#
#**********************decrypt route***********************#
#***************************************************************# 
@app.route('/decrypt/<int:message_id>', methods=['GET', 'POST'])
@login_required
def decrypt_message(message_id):
    user_id = session.get('user_id')  
    plaintext_message = ' '  # Initialize the decrypted message as None

    if request.method == 'POST':
        private_key_data = request.form.get("privatekey")

        if not private_key_data:
            flash("Private key is required for decryption.", "error")
            return render_template('decrypt.html', message_id=message_id, plaintext_message=plaintext_message)

        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_data.encode(),
                password=None
            )

            # Fetch message data from DB
            con = mysql.connect()
            cur = con.cursor()
            cur.execute("""
                SELECT EncryptedSharedKeyReceiver, EncryptedSharedKeySender, Content, SenderID, RecipientID 
                FROM message
                WHERE MessageID = %s
            """, (message_id,))
            result = cur.fetchone()
            cur.close()
            con.close()

            if not result:
                flash("Message not found.", "error")
                return render_template('decrypt.html', message_id=message_id, plaintext_message=plaintext_message)

            encrypted_shared_key_receiver, encrypted_shared_key_sender, cipher_text, sender_id, receiver_id = result
            
            # Determine which shared key to use
            encrypted_shared_key = (
                encrypted_shared_key_receiver if user_id == receiver_id else encrypted_shared_key_sender
            )

            # Decode keys and ciphertext
            encrypted_shared_key_bytes = base64.b64decode(encrypted_shared_key)
            encrypted_message_bytes = base64.b64decode(cipher_text)
            iv, ciphertext = encrypted_message_bytes[:16], encrypted_message_bytes[16:]

            # Decrypt symmetric key
            symmetric_key = private_key.decrypt(
                encrypted_shared_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt message
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plaintext_message = decryptor.update(ciphertext) + decryptor.finalize()

            # Render the decrypted message on the same page
            flash("Message decrypted successfully!", "success")
            return render_template('decrypt.html', message_id=message_id, plaintext_message=plaintext_message.decode())

        except Exception as e:
            flash(f"Decryption failed please try agian", "error")
            return render_template('decrypt.html', message_id=message_id, plaintext_message=plaintext_message)

    # Render the decrypt page for GET requests
    return render_template('decrypt.html', message_id=message_id, plaintext_message=plaintext_message)


#**************************************************************#
#**********************encrypt route****************************#
#***************************************************************#
@app.route("/encrypt", methods=["POST"])
@login_required
# Encrypt a message and validate the receiver's email.
def encrypt_message():

    receiver_email = request.form.get("receiverEmail")
    message = request.form.get("message")

    if not receiver_email or not message:
        flash("Receiver's email and message are required.", "danger")
        return redirect(url_for("encryptionPage"))

    con = mysql.connect()
    cur = con.cursor()
    cur.execute("SELECT user_id, certificate FROM users WHERE email = %s", (receiver_email,))
    result = cur.fetchone()

    if not result:
        cur.close()
        con.close()
        flash("The receiver's email is not found in the database. Please try again.", "danger")
        return redirect(url_for("encryptionPage"))

    receiver_id, receiver_certificate_pem = result
    cur.close()
    con.close()

    try:
        receiver_certificate = x509.load_pem_x509_certificate(receiver_certificate_pem.encode(), default_backend())
        receiver_public_key = receiver_certificate.public_key()

        # Generate keys and encrypt the message
        symmetric_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = base64.b64encode(
            iv + encryptor.update(message.encode()) + encryptor.finalize()
        ).decode()

        # Encrypt the symmetric key twice
        encrypted_key_receiver = receiver_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Also encrypt the symmetric key with sender's public key (you need sender's public key here)
        sender_public_key = get_sender_public_key(session.get("user_id"))  # You need to define this function
        encrypted_key_sender = sender_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Store in the database
        con = mysql.connect()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO message (EncryptedSharedKeyReceiver, EncryptedSharedKeySender, Content, SenderID, RecipientID)
            VALUES (%s, %s, %s, %s, %s)
        """, (base64.b64encode(encrypted_key_receiver).decode(),
              base64.b64encode(encrypted_key_sender).decode(),
              encrypted_message, session.get("user_id"), receiver_id))
        con.commit()
        cur.close()
        con.close()

        flash("Message encrypted and sent successfully.", "success")


        # Return to the encryption page with the results
        return render_template(
            "encryptionPage.html",
            encrypted_message=encrypted_message,
            encrypted_key_receiver=base64.b64encode(encrypted_key_receiver).decode(),
            encrypted_key_sender=base64.b64encode(encrypted_key_sender).decode()
        )
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for("encryptionPage"))

def get_sender_public_key(sender_id):
    con = mysql.connect()
    cur = con.cursor()
    
    # Query the sender's public key from the database (assuming it's stored in the users table)
    cur.execute("SELECT certificate FROM users WHERE user_id = %s", (sender_id,))
    sender_certificate_pem = cur.fetchone()

    if sender_certificate_pem:
        sender_certificate = x509.load_pem_x509_certificate(sender_certificate_pem[0].encode(), default_backend())
        sender_public_key = sender_certificate.public_key()
        cur.close()
        con.close()
        return sender_public_key
    else:
        cur.close()
        con.close()
        raise Exception("Sender's certificate not found in the database.")
    
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
        con = mysql.connect()
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
            con = mysql.connect()
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
#**********************Signup route************************#
#**********************************************************#
@app.route("/signupsafe1", methods=['GET', 'POST'])
#Handle user resistration
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
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) #Many hashing algorithms, including bcrypt, require the input to be in byte format, so encoding is necessary.


        # Store private key in the session
        session['private_key'] = base64.b64encode(private_key).decode()
        session['user_id'] = cur.lastrowid  # Store user ID in session
        
        # Store user details in session instead of the database
        session['user_name'] = user_name
        session['email'] = email
        session['password'] = password
        session['certificate'] = certificate
        
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
#**********************loginsafe route*******************#
#**********************************************************#    
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
            stored_hashed_password = user[3]  #the password is stored in the 3rd column (index 3)

            # Check if the hashed password matches the entered password
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                session['user_id'] = user[0]  
                session['user_name'] = user[1]  
                
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
    con.close()
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
            con = mysql.connect()
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


#**********************************************************#
#*********************resend_otp route*******************#
#**********************************************************#    
@app.route("/resend_login_otp")
#Handle OTP resend requests for login verification.
def resend_login_otp():
    # Check if the user is allowed to request a new OTP
    if session.get("otp_block_until") and datetime.datetime.utcnow() < session["otp_block_until"]:
        # If the block period has not expired yet, inform the user to wait
        block_until = session["otp_block_until"]
        remaining_time = block_until - datetime.datetime.utcnow()
        remaining_minutes = remaining_time.seconds // 60
        remaining_seconds = remaining_time.seconds % 60

        if remaining_minutes == 0 and remaining_seconds > 0:
            remaining_message = f" '<span style='color:red;'> Please wait for the remaining time: {remaining_seconds} seconds.</span>"
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
#Handle OTP resend requests for registration verification.
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
    con = mysql.connect()
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

        con = mysql.connect()
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
        con = mysql.connect()
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
