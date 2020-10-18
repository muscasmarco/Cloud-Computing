from flask import Flask, jsonify, make_response, request
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta
import json
from flask import render_template
import uuid

app = Flask(__name__)
app.config.from_pyfile('db_config.cfg')
db = MongoEngine(app)

class User(db.Document):
    _id = db.IntField(primary_key = True)
    public_id = db.StringField(unique = True)
    email = db.StringField(unique = True)
    password = db.StringField() 
    registered_serial_numbers = db.ListField(default = [])
    if_admin = db.BooleanField(default = False)


    def to_json(self):
        raw_json = {"public_id":self.public_id,
                    "email":self.email,
                    "password":self.password,
                    "registered_serial_numbers":self.registered_serial_numbers,
                    "if_admin":self.if_admin}
        return raw_json

class Product(db.Document):
    _id = db.IntField(primary_key = True)
    product_id = db.StringField(required = True, unique = True)
    name = db.StringField(required = True, max_length = 100)
    image_url = db.StringField(required = False)

    def to_json(self):
        raw_json = {'product_id':self.product_id,
                    'name':self.name,
                    'image_url':self.image_url}
        return raw_json

class SerialNumber(db.Document):

    _id = db.StringField(primary_key = True)
    value = db.StringField(required = True, unique = True)
    registration_date = db.StringField()
    registration_user = db.StringField() # ID of the registering user
    product = Product()


    def to_json(self):
        raw_json = {'value':self.value, 
                    'registration_date':self.registration_date,
                    'registration_user':self.registration_user,
                    'product':self.registration_user
                    }
        return raw_json


# ------------------------------------------- Decorators -----------------------------------------
# Create a decorator to apply for the endpoints that require authentication
def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = ad_users.objects(user_id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        if current_user.to_json()["if_admin"]:

            return f(current_user, *args, **kwargs)
        else :
            return jsonify({'message': "You can't access this page"}), 401

    return decorated



# -------------------------------------------- User API endpoints ---------------------------------- 


@app.route('/api/user/register', methods = ['POST'])
def register():

    request_content = request.get_json()

    try:

        email = request_content['email']
        password = request_content['password']
        
        User.objects.insert(User(public_id = str(uuid.uuid4()), email = email,
                                 password = password, registered_serial_numbers = []))
    except Exception as e:
        return jsonify({'code':400, 'message':str(e)})

    return make_response('User registered successfully.', 201)


@app.route('/api/user/', methods = ['GET'])
def get_all_users():
    return jsonify({'users':User.objects})

@app.route('/api/user/<public_id>', methods = ['GET'])
def get_user_by_id(public_id):
    return jsonify({'user':User.objects(public_id = public_id).first()})

@app.route('/api/user/delete_all', methods = ['GET'])
def delete_all_users():
    User.drop_collection()
    return jsonify({'users':User.objects})


@app.route('/api/user/delete/', methods = ['POST'])
def delete_user():
    try:

        content = request.get_json()
        email = content['email']

        User.objects(email = email).delete()

    except Exception as e:
        return jsonify({'code':400, 'message':str(e)})

    return jsonify({'code':200, 'message':'ok'})
        
# -------------------------------     Serial number API endpoints ----------------------------------
'''

@app.route('/api/serial_number/<sn>', methods=["GET"])
def search_sn(sn):
    serial_object = SerialNumber.objects(value = sn).first()
    if serial_object:
        return make_response(jsonify(serial_object.to_json()), 200)
    else:
        return make_response('', 404)

@app.route('/api/add_serial_number/', methods = ['POST'])
def add_serial_number(): # Requires a JSON to be sent
    
    try:
        content = request.get_json()
   
        value = content['value']
        registration_date = content['registration_date']
        registration_user = content['registration_user']
        product = content['product']
    
        SerialNumber.objects.insert(SerialNumber(value = value,
                                             registration_date = registration_date,
                                             registration_user = registration_user,
                                             product = product))

    except Exception as e:
        
        return jsonify({'code':400, 'message':str(e)})

    return jsonify({'code':200, 'message':'ok'})

'''    
# -------------------------------------------------------------- Products API endpoints ------------------------------------------------------------------- 

'''
@app.route('/api/products/', methods = ['GET'])
def get_all_products():
    return jsonify(Product.objects)


@app.route('/api/products/<product_id>', methods = ['POST'])
def get_product_by_id(product_id):
    product_object = Product.objects(product_id == product_id).first

    if product_object:
        return jsonify(product_object)
    
    return jsonify({'code':404, 'message':"Product not found."})

@app.route('/api/product/insert', methods = ['POST'])
def insert_new_product():
    try:
        content = request.get_json()

        product_id = content['product_id']
        name = content['name']
        image_url = content['image_url']

        Product.objects.insert(Product(product_id = product_id, name = name, image_url = image_url))
        
        return jsonify({'code':200, message:'ok'})


    except Exception as e:
        return jsonify({'code':400, 'message':str(e)})
    
@app.route('/api/product/delete/<product_id>')
def delete_product(product_id):
    try:
        product_object = Product.objects(product_id == product_id).first()
        Product.objects.delete_one(product_object)
    except Exception as e:
        return jsonify({'code':400, 'message':str(e)})

    return jsonify({'code':200})

'''

# -------------------------------   Login endpoint   ----------------------------------


@app.route("/api/user/login", methods = ['POST'])
def login():
    print('User is trying to log in')
    auth = request.get_json()['authorization']
    
    if not auth:
        return make_response('Auth missing', 401, {'WWW-Authenticate':'Basic realm="Login required!'})

    if not auth or ('email' not in auth.keys()) or ('password' not in auth.keys()):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    email = auth['email']
    password = auth['password']

    user = User.objects(email=email).first()

    if not user:
        return make_response('Could not verify1', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if password == user.password:
        user_expire_session = '100000'

        print('Login successful')
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': user_expire_session}, app.config['SECRET_KEY'])

        token = token.decode('UTF-8')
        return jsonify({'token': token})

    return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})






@app.route("/", methods = ['GET'])
def testing_homepage():
    return "Your container is working"

if __name__ == '__main__':
    #app.run(host = "0.0.0.0", port = 80, debug = False)
    app.run(host = "127.0.0.1", port = 5000, debug = True)

