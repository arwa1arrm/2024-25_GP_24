from flask import Flask
from flask_mysqldb import MySQL
import pymysql
pymysql.install_as_MySQLdb()

app = Flask(__name__)

# Database configuration for JawsDB (from Heroku)
app.config['MYSQL_HOST'] = 'nwhazdrp7hdpd4a4.cbetxkdyhwsb.us-east-1.rds.amazonaws.com'
app.config['MYSQL_USER'] = 'p9prwattomm16p3g'
app.config['MYSQL_PASSWORD'] = 'c9q4ryabzpusia3y'
app.config['MYSQL_DB'] = 'dtrqo2npjnal12vl'
# Initialize the MySQL object
mysql = MySQL(app)

@app.before_first_request
def test_db_connection():
    try:
        # Print to check connection
        print("Trying to connect to MySQL database...")
        
        # Check if mysql.connection is properly initialized
        if mysql.connection is None:
            raise Exception("Failed to connect to the database: mysql.connection is None")
        
        # Test the connection by pinging the MySQL server
        mysql.connection.ping()
        print("Connected to database successfully!")
        
    except Exception as e:
        print(f"Failed to connect: {str(e)}")
        # Return a message in case of failure
        return f"Failed to connect to the database: {str(e)}"

@app.route('/')
def index():
    try:
        # Check if the connection is valid
        if mysql.connection is None:
            return "Failed to connect to the database!"
        
        # Attempt to get a cursor object and execute a query
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM message')
        messages = cur.fetchall()

        return str(messages)
    
    except Exception as e:
        print(f"Error in query execution: {str(e)}")
        return f"An error occurred: {str(e)}"  # Return the error message if connection fails

if __name__ == "__main__":
    app.run(debug=True)
