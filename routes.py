import base64
import io
from flask import render_template, session, redirect, request, url_for, flash
from functools import wraps
from flask import send_file 

# Import the User and CertificateManager classes
from user import User
from certificate_manager import CertificateManager


# Import the User and CertificateManager classes
from user import User
from certificate_manager import CertificateManager

class Routes:
    def __init__(self, app, mysql):
        self.app = app
        self.mysql = mysql
        self.user = User(mysql)
        self.certificate_manager = CertificateManager()
        self.register_routes()

    def login_required(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('loginsafe'))
            return f(*args, **kwargs)
        return decorated_function

    def register_routes(self):
        @self.app.route("/")
        def homepage():
            return render_template('homepage.html')

        @self.app.route("/userHomePage")
        @self.login_required
        def userHomePage():  # Maintained original naming
            user_name = session.get('user_name')
            return render_template('userhomepage.html', user_name=user_name)

        @self.app.route("/signupsafe1", methods=['GET', 'POST'])
        def signupsafe1():  # Maintained original naming
            if request.method == 'POST':
                user_name = request.form['user_name']
                email = request.form['email']
                password = request.form['password']

                private_key, certificate = self.certificate_manager.generate_keys_and_certificate(user_name)
                self.user.register(user_name, email, password, certificate.decode('utf-8'))

                session['private_key'] = private_key.decode('utf-8')
                return render_template('registration_confirmation.html', user_name=user_name)

            return render_template('signupsafe1.html')

        @self.app.route("/loginsafe", methods=['GET', 'POST'])
        def loginsafe():  # Maintained original naming
            if request.method == 'POST':
                email = request.form['email']
                password = request.form['password']

                user = self.user.get_user_by_email(email)
                if user and self.user.check_password(password, user[3]):
                    session['user_id'] = user[0]
                    session['user_name'] = user[1]
                    return redirect(url_for('userHomePage'))  # Maintained original naming
                else:
                    return render_template('loginsafe.html', error="Invalid email or password")
            
            return render_template('loginsafe.html')

        @self.app.route("/logout")
        def logout():  # Maintained original naming
            session.clear()
            flash('You have been logged out.', 'info')
            return redirect(url_for('homepage'))

        @self.app.route("/ForgotPassword", methods=['GET', 'POST'])
        def ForgotPassword():  # Maintained original naming
            if request.method == 'POST':
                email = request.form['email']
                flash('If this email is registered, you will receive a reset link.', 'info')
                return redirect(url_for('homepage'))

            return render_template('forgotPassword.html')

        @self.app.route("/messages")
        @self.login_required
        def messages():  # Maintained original naming
            return render_template('messages.html')

        @self.app.route("/decrypt")
        @self.login_required
        def decrypt():  # Maintained original naming
            return render_template('decrypt.html')

        @self.app.route("/encryptionPage")
        @self.login_required
        def encryptionPage():  # Maintained original naming
            return render_template('encryptionpage.html')

        @self.app.route("/viewprofile")
        @self.login_required
        def viewprofile():  # This matches the original naming
         return render_template('viewprofile.html')  # Ensure this matches your HTML file


        @self.app.route("/download_private_key")
        @self.login_required
        def download_private_key():
            private_key_b64 = session.get('private_key')

            if private_key_b64:
                private_key = base64.b64decode(private_key_b64)
                return send_file(
                io.BytesIO(private_key),
                as_attachment=True,
                attachment_filename='private_key.pem',
                mimetype='application/x-pem-file'
                             )
            else:
                return "Private key not found", 404

