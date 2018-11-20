"""
Webserver display upcoming buses
"""
import os
import sys
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, Response, redirect, jsonify
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from flask_wtf import FlaskForm
import json
import requests
from datetime import datetime, timezone
import dateutil.parser
import pytz
from sqlalchemy.ext.declarative import declarative_base
from collections import OrderedDict
import time

SECRET_LENGTH = 24

#sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common import get_config, get_uri


debug = 'DEBUG' in os.environ and os.environ['DEBUG'] == "on"
debug_with_cache = 'DEBUG_WITH_CACHE' in os.environ and os.environ['DEBUG_WITH_CACHE'] == "on"
CACHE_PATH = os.path.join(os.path.dirname(__file__), "cache")

if debug_with_cache:
    os.system("mkdir -p '" + CACHE_PATH + "'")


app = Flask("Bus dashbaord", template_folder=os.path.join(os.path.dirname(__file__), "templates"))


def set_app_db(a):
    settings = get_config()
    a.config["SQLALCHEMY_DATABASE_URI"] = get_uri(settings)
    a.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    return


set_app_db(app)

db = SQLAlchemy(app)


# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

login_manager.init_app(app)
Bootstrap(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = generate_password_hash(password, method='sha256')

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name)


Base = declarative_base()


class AppConfig(Base):
    __tablename__ = "app_config"
    id = db.Column(db.Integer, primary_key=True)
    secret = db.Column(db.BINARY(SECRET_LENGTH), unique=True)

    def __init__(self, id , secret):
        self.id = id
        self.secret = secret

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name)


def init_db(uri):
    """
    Checks if db is init, if not inits it

    :return:
    """
    engine = create_engine(uri)
    User.metadata.create_all(engine)
    AppConfig.metadata.create_all(engine)

    # Add admin if does not exist

    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()

    user = session.query(User).first()
    if user is None:
        settings = get_config()
        entry = User(id=0, username="admin", password=settings["webserver"]["init_password"])
        session.add(entry)
        session.commit()
        print('First run, created database with user admin')

    app_config = session.query(AppConfig).first()
    if app_config is None:
        entry = AppConfig(id=0, secret=os.urandom(SECRET_LENGTH))
        session.add(entry)
        session.commit()
        print('First run, created table with secret key for sessions')

        app_config = session.query(AppConfig).first()

    app.config["SECRET_KEY"] = app_config.secret
    return


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])
    remember = BooleanField('remember me')


def cache_get(url, params=None):
    headers = {"Accept": "application/json"}

    if debug_with_cache:
        if params is not None:
            hash = url + str(OrderedDict(sorted(params.items())))
        else:
            hash = url
        cache_path = os.path.join(CACHE_PATH, hash.replace("/","") + ".json")

        if os.path.isfile(cache_path):
            return json.load(open(cache_path))

    # Else we need to pull and save

    if params is not None:
        response = requests.get(url, headers=headers, params=params)

    else:
        response = requests.get(url, headers=headers)

    try:
        data = response.json()

        if debug_with_cache:
            json.dump(data, open(cache_path, "w"))

        return data
    except:
        print("Fail to do request")
        return


def has_numbers(input):
    return any(char.isdigit() for char in input)

def get_dashboard_data(lon, lat):

    stations_data = cache_get("https://curlbus.app/nearby",  {"lat": str(lat),
                                                          "lon": str(lon),
                                                          "radius": "500"})

    if stations_data is None:
        return

    stations = {}
    for station_data in stations_data:
        stations[station_data["code"]] = station_data

    visiting_buses = []

    print("stations: " + str(len(stations)))

    for station in stations.keys():
        url = "https://curlbus.app/" + str(station)
        data = cache_get(url)

        print(station)
        print(data["stop_info"])

        # Take each visit and add to it static information to display about it
        for i, visit in enumerate(data["visits"][str(station)]):
            data["visits"][str(station)][i]["stop_name"] = data["stop_info"]["name"]["HE"]
            data["visits"][str(station)][i]["stop_id"] = station
            data["visits"][str(station)][i]["stop_street"] = data["stop_info"]["address"]["street"]
            data["visits"][str(station)][i]["location"] = data["stop_info"]["location"]

        visiting_buses += data["visits"][str(station)]

    # We got all the data, now lets format it

    for i, visit in enumerate(visiting_buses):
        # print(visit.keys())
        eta_delta = dateutil.parser.parse(visit["eta"]) - datetime.now(pytz.timezone('Asia/Jerusalem'))
        eta_min = int(eta_delta.seconds/60)
        visiting_buses[i]["eta_min"] = eta_min

    # visiting_buses = sorted(visiting_buses, key=lambda x: x["eta_min"])
    visiting_buses = sorted(visiting_buses, key=lambda x: x["line_name"])

    def make_line_id(line):
        return line["line_name"] + "|" + line["static_info"]["route"]["destination"]["name"]["HE"]

    # Kill double location
    groupped_lines = []
    groupped_lines_ids = {}

    MAX_MINTUES = 3*60

    for i, visit in enumerate(visiting_buses):
        if visit["eta_min"] < MAX_MINTUES:
            visit["eta_min"] = [visit["eta_min"]]

            first_insert = False
            if make_line_id(visit) not in groupped_lines_ids.keys():
                first_insert = True
                groupped_lines_ids[make_line_id(visit)] = len(groupped_lines)
                groupped_lines.append(visit)
            # Now we have a visit, and the id of the line it represents
            stored_id = groupped_lines_ids[make_line_id(visit)]

            if stations[visit["stop_id"]]["distance"] < stations[groupped_lines[stored_id]["stop_id"]]["distance"]:
                # This is the same line and is coming from a closer station, trash all we did and use this station
                groupped_lines[stored_id] = visit
            elif visit["stop_id"] == groupped_lines[stored_id]["stop_id"] and not first_insert:
                groupped_lines[stored_id]["eta_min"] += visit["eta_min"]
                groupped_lines[stored_id]["eta_min"] = sorted(groupped_lines[stored_id]["eta_min"])

        # Sort by which bus arrives soonest
    groupped_lines = sorted(groupped_lines, key=lambda x: x["eta_min"])


    # Now lets group by station
    grouped_stations = {}
    for visit in groupped_lines:
        if has_numbers(visit["stop_street"]):
            key = visit["stop_street"]
        else:
            key = visit["stop_name"] + ", " +  visit["stop_street"] + " (" + visit["stop_id"] + ")"
        # visit["static_info"]["route"]["destination"]["name"]["HE"] + " - " + visit["stop_street"]
        if key not in grouped_stations:
            grouped_stations[key] = []
        grouped_stations[key].append(visit)

    print("total boards:")
    print(len(grouped_stations))
    return grouped_stations


@app.route("/data", methods=['GET', 'POST'])
def data():
    lon = request.values.get('lon')
    lat = request.values.get('lat')
    grouped_stations = get_dashboard_data(lon, lat)
    return jsonify(grouped_stations)


@app.route("/buses", methods=['GET', 'POST'])
def buses():
    lon = request.values.get('lon')
    lat = request.values.get('lat')
    grouped_stations = get_dashboard_data(lon, lat)
    return render_template("busses.jinja2", visiting_buses=grouped_stations)


@app.route("/")
def root():
    return render_template("index.jinja2")


@app.route("/live")
def live():
    return render_template("live.jinja2")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user is not None and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect('/')
        else:
            form.password.errors.append('Invalid username or password')

    return render_template('login.jinja2', form=form)

@app.route('/test', methods=['GET', 'POST'])
def test():
    return str(time.time())


# somewhere to logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return Response('<p>Logged out</p>')


# handle login failed
@app.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')


# callback to reload the user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def run():
    settings = get_config()
    app.run(debug=debug, host='0.0.0.0', port=int(settings["webserver"]["port"]), threaded=True)
    return


if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from common import get_config, get_uri_without_db
    from database import mysql_init_db

    settings = get_config()
    mysql_init_db(get_uri_without_db(settings), settings)
    run()


