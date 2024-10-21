from app_config import AppConfig
from routes import Routes

if __name__ == "__main__":
    config = AppConfig()
    app = config.get_app()
    mysql = config.get_mysql()
    
    # Initialize routes
    Routes(app, mysql)

    # Run the app
    app.run(debug=True)
