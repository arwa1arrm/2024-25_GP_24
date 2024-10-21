import bcrypt

class User:
    def __init__(self, mysql):
        self.mysql = mysql

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password, hashed_password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    def register(self, user_name, email, password, certificate):
        hashed_password = self.hash_password(password)
        conn = self.mysql.connect()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO `users`(`user_name`, `email`, `password`, `certificate`) VALUES (%s, %s, %s, %s)",
                       (user_name, email, hashed_password, certificate))
        conn.commit()
        cursor.close()
        conn.close()

    def get_user_by_email(self, email):
        conn = self.mysql.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user
