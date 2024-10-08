from flask import Flask, render_template, request, redirect, flash # type: ignore
import mysql.connector # type: ignore
import bcrypt  # type: ignore # Add this for hashing passwords

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For flashing messages

# MySQL Database configuration
db_config = {
    'user': 'root',        # MySQL username
    'password': 'root',    # MySQL password
    'host': '127.0.0.1',   # MySQL server (localhost for MAMP)
    'port': '8889',        # MySQL port (MAMP default is 8889)
    'database': 'concealsafedb'  # Your MySQL database name
}

# Route for the Sign-Up form
@app.route('/signupsafe1', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password before saving it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the data into the MySQL database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        try:
            # Use the correct column names from your table
            query = "INSERT INTO user (Username, Email, PasswordHash) VALUES (%s, %s, %s)"
            cursor.execute(query, (username, email, hashed_password))
            conn.commit()
            flash('User registered successfully!', 'success')  # Success message
        except Exception as e:
            flash(f"Error: {str(e)}", 'danger')  # Error message if insertion fails
        finally:
            cursor.close()
            conn.close()

        return redirect('/signupsafe1')

    # For GET request, render the signup.html page
    return render_template('signupsafe1.html')

if __name__ == '__main__':
    app.run(debug=True)


##What does this code do?
#app.py is where your Flask code lives.
#It handles form submissions and stores the data into your MySQL database.
#It serves the Sign-Up page by rendering the signup.html file (which we will create next).
