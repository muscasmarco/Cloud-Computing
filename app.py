from flask import Flask, jsonify, make_response, request
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta
import json

app = Flask(__name__)

# The secrete key to encode the token for JWT
app.config["SECRET_KEY"] = "thisiscool"

db_pass = 'clc2020_nice_password'
db_name = 'clc2020_sys_db'

#db_URL = "mongodb+srv://Admin1:{}@myfirstcluster.l6ygq.mongodb.net/{}?retryWrites=true&w=majority".format(
#    mongoDB_pass, database_name)

db_URL = 'mongodb+srv://clc_db_admin:{}@clusterclc.sfbwf.mongodb.net/{}?retryWrites=true&w=majority'.format(db_pass, db_name)
app.config["MONGODB_HOST"] = db_URL
db = MongoEngine()
db.init_app(app)


# Define a collections for the users that can edit database
class ad_users(db.Document):
    user_id = db.IntField()
    user_name = db.StringField()
    user_pass = db.StringField()


# Define a serial_num collection
class serial_num(db.Document):
    sn_id = db.IntField()
    sn = db.StringField()
    name = db.StringField()
    date = db.StringField()

    def to_json(self):
        # convert this document to json
        return {
            "serial number": self.sn,
            "product Type": self.name,
            "production date": self.date
        }


# inserting data to our collection object
'''
serial_num.objects.insert([serial_num(sn_id=1, sn="456689234120", name="Headphone Bluetooth", date="23/04/2019"),
                           serial_num(sn_id=2, sn="729845013482", name="External disc", date="12/06/2018"),
                           serial_num(sn_id=3, sn="863299208534", name="Kindle", date="14/04/2018"),
                           serial_num(sn_id=4, sn="457873547585", name="Headphone Bluetooth", date="02/05/2019"),
                           serial_num(sn_id=5, sn="867394764648", name="Kindle", date="16/07/2018"),
                           serial_num(sn_id=6, sn="866689849920", name="Kindle", date="13/04/2018")])
'''

# Adding data to our ad_users collection object
#ad_users.objects.insert([ad_users(user_id=1, user_name="student1", user_pass="cloud2020")])

@app.route('/create_user/', methods = ['GET'])
def create_user():
    ad_users.objects.insert([ad_users(user_id=1, user_name="student1", user_pass="cloud2020")])
    return "User created"

# Create a decoraotr to apply for the endpoints that require authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = ad_users.objects(user_id=data['user_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


#The endpoint to see the info about a serial number
@app.route('/api/<sn>', methods=["GET"])
def search_sn(sn):
    serial_object = serial_num.objects(sn=sn).first()
    if serial_object:
        return make_response(jsonify(serial_object.to_json()), 200)
    else:
        return make_response("", 404)


# The endpoint to add serial number to the serial_num database
# This route need authentication and only predefined admins can access it after login
@app.route("/api/addSN", methods = ["POST"])
@token_required
def add_serialNum(current_user):
    content = request.json
    serial_num.objects.insert([serial_num(sn_id=content.sn_id, sn=content.sn,
                                          name=content.name, date=content.date)])

    return make_response("A new serial number has been populated",201)


@app.route("/login")
def login():
    print('User is trying to log in')
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    User = ad_users.objects(user_name = auth.username).first()


    if not User:
        return make_response('Could not verify1', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    pass_true = ad_users.objects(user_pass = auth.password).first()
    if pass_true:

        user_username = str(ad_users.user_name)
        user_expire_session = '100000'

        print('Login successful')
        token = jwt.encode(
            {'username': user_username, 'exp': user_expire_session}, app.config['SECRET_KEY'])
        
        token = token.decode('UTF-8')
        return jsonify({'token':token})

    return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug='True')
