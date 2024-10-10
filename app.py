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
def home():
    return render_template('homepage.html')

@app.route("/signupsafe1",methods=['GET','POST'])
def signupsafe1():
    

    return render_template('signupsafe1.html')

@app.route("/loginsafe",methods=['GET','POST'])
def loginsafe():
    #connection
    con=mysql.connect()
    cur=con.cursor()
    if request.method=="POST":
        first_name=request.form['first_name']
        last_name=request.form['last_name']
        email=request.form['email']
        password=request.form['password']
        cur.execute("INSERT INTO `users`(`first_name`, `last_name`, `email`, `password`) VALUES (%s,%s,%s,%s)",(first_name,last_name,email,password))
        con.commit()
        return redirect(url_for('home'))
    else:
        return render_template('loginsafe.html')

if __name__=="__main__":
    app.run(debug=True)