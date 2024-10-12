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

@app.route("/signupsafe1",methods=['GET','POST'])
def signupsafe1():
     #connection
    con=mysql.connect()
    cur=con.cursor()
    if request.method=="POST":
        user_name=request.form['user_name']
        email=request.form['email']
        password=request.form['password']
        cur.execute("INSERT INTO `users`(`user_name`, `email`, `password`) VALUES (%s,%s,%s)",(user_name,email,password))
        con.commit()
        return redirect(url_for('loginsafe'))
    else:
         return render_template('signupsafe1.html')
    
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

    return render_template('loginsafe.html')


if __name__=="__main__":
    app.run(debug=True)