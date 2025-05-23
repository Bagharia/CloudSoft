from flask import Flask
from mongodb.config.connection_db import get_database
from api.routes.auth import auth_bp 
from flask_cors import CORS
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)

db = get_database()

app.register_blueprint(auth_bp, url_prefix='/api/auth')

@app.route('/')
def index():
    return 'Welcome to AIsoft!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)