from flask import Flask
from flaskext.mysql import MySQL

class AppConfig:
    def __init__(self):
        self.app = Flask(__name__)
        self.mysql = MySQL()
        self.configure_app()

    def configure_app(self):
        # Configure secret key and MySQL settings
        self.app.secret_key = 'g5$8^bG*dfK4&2e3yH!Q6j@z'
        self.app.config['MYSQL_DATABASE_USER'] = 'root'
        self.app.config['MYSQL_DATABASE_PASSWORD'] = 'root'
        self.app.config['MYSQL_DATABASE_DB'] = 'concealsafe'
        self.app.config['MYSQL_DATABASE_HOST'] = 'localhost'
        self.mysql.init_app(self.app)

    def get_app(self):
        return self.app

    def get_mysql(self):
        return self.mysql
