from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os 
from routes.main import main
from extensions import db
import psycopg2 
from .routes.main import main
from .routes.api import api


app = Flask(__name__)

# Configure PostgreSQL with the  psycopg2 driver.
url = f'postgresq+psycopg2://{os.environ["DB_USER"]}:${os.environ["DB_PASSWORD"]}@localhost/{os.environ["DB_DATABASE"]}'
db_uri = db.url_for_postgresql(url)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)
engine = db.create_


app.register_blueprint(api)
app.register_blueprint(main)


if __name__ == '__main__':
    app.run(debug=True)