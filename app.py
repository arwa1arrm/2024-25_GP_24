from flask import Flask,render_template,url_for,request,redirect 

#import flask mysql
from flaskext.mysql import MySQL 

mysql=MySQL()

#initialize flask components in app varible
app = Flask(__name__)

#configure mysql with flask app 
app.config['MYSQL_DATABASE_USER']='root'
app.config['MYSQL_DATABASE_PASSWORD']='root'
app.config['MYSQL_DATABASE_DB']='concealsafe'
app.config['MYSQL_DATABASE_HOST']='localhost'

#initialize app
mysql.init_app(app)

@app.route("/")
def homepage():
    return render_template('homepage.html')


@app.route("/userHomePage")
def userHomePage():
    return render_template('userHomePage.html')


import re
@app.route("/signupsafe1", methods=['GET', 'POST'])
def signupsafe1():
    # Database connection
    con = mysql.connect()
    cur = con.cursor()

    if request.method == "POST":
        user_name = request.form['user_name']
        email = request.form['email']
        password = request.form['password']

        email_pattern = r'^[\w._%+-]+@[a-zA-Z0-9.-]+\.[cC][oO][mM]$'
        if not re.match(email_pattern, email):
            return render_template('signupsafe1.html', error="Invalid email format. Please enter a valid email (e.g., user@domain.com).")

        
        # Check if the user with the given email already exists
        cur.execute("SELECT * FROM `users` WHERE `email` = %s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            # If the email is already used, render the signup page with an error message
            return render_template('signupsafe1.html', error="Email is already used. Please log in directly.")
        else:
            # Insert the new user into the database
            cur.execute("INSERT INTO `users` (`user_name`, `email`, `password`) VALUES (%s, %s, %s)", (user_name, email, password))
            con.commit()

            # Show a success message on the same page and redirect to login page after a delay
            return render_template('signupsafe1.html', alert="Successful registration! You will be redirected to login shortly.")
    
    # Close connection after handling request
    cur.close()
    con.close()

    return render_template('signupsafe1.html')



    
     
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
        cur.execute("SELECT * FROM `users` WHERE `email`=%s AND `password`=%s", (email, password))
        user = cur.fetchone()

        if user:
            # If user is found, redirect to homepage
            return redirect(url_for('userHomePage'))
        else:
            # If login fails, return to login page with an error message
            return render_template('loginsafe.html', error="Invalid email or password")

    return render_template('loginsafe.html')  # default page load


if __name__=="__main__":
    app.run(debug=True)