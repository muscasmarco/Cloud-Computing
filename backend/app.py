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



class Product(db.Document):
    _id = db.IntField(primary_key=True)
    product_id = db.StringField(required=True, unique=True)
    name = db.StringField(required=True, max_length=100)
    image_url = db.StringField(required=False)

    def to_json(self):
        raw_json = {'product_id': self.product_id,
                    'name': self.name,
                    'image_url': self.image_url}
        return raw_json


class SerialNumber(db.Document):
    _id = db.StringField(primary_key=True)
    value = db.StringField(required=True, unique=False)
    registration_date = db.StringField()
    registration_user = db.StringField()  # ID of the registering user
    product_id = db.StringField(required = True)

    def to_json(self):
        raw_json = {'value': self.value,
                    'registration_date': self.registration_date,
                    'registration_user': self.registration_user,
                    'product_id': self.product_id
                    }
        return raw_json


class User(db.Document):
    _id = db.IntField(primary_key=True)
    public_id = db.StringField(unique=True)
    email = db.StringField(unique=True)
    password = db.StringField()
    registered_serial_numbers = db.ListField(SerialNumber, default=[])
    if_admin = db.BooleanField(default=False)

    def to_json(self):
        raw_json = {"public_id": self.public_id,
                    "email": self.email,
                    "password": self.password,
                    "registered_serial_numbers": self.registered_serial_numbers,
                    "if_admin": self.if_admin}
        return raw_json


# ------------------------------------------- Decorators -----------------------------------------
# Create a decorator to apply for the endpoints that require admin authentication
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
            current_user = User.objects(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'exception':str(e)}), 401

        if current_user.to_json()["if_admin"]:

            return f(*args, **kwargs)
        else:
            return jsonify({'message': "You can't access this page"}), 401

    return decorated


# Create a decorator to apply for the endpoints that require user authentication
def login_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.objects(public_id = data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)

    return decorated


# -------------------------------------------- User API endpoints ----------------------------------


@app.route('/api/user/register', methods=['POST'])
def register():

    request_content = request.get_json()
    return jsonify({'content':str(request_content)})
    try:

        email = request_content['email']
        password = request_content['password']
        
        if 'admin_key' in request_content.keys():        
            admin_key = request_content['admin_key']

            if admin_key == app.config['ADMIN_REGISTRATION_KEY']:
                User.objects.insert(User(public_id=str(uuid.uuid4()), email=email, password=password, 
                                        registered_serial_numbers=[], if_admin = True))

        else:
            User.objects.insert(User(public_id=str(uuid.uuid4()), email=email, password=password, registered_serial_numbers=[]))

    except Exception as e:
        return jsonify({'code': 400, 'message': str(e)})

    return make_response('User registered successfully.', 201)

@app.route('/api/user/', methods=['GET'])
def get_all_users():
    return jsonify({'users': User.objects})


@app.route('/api/user/<public_id>', methods=['GET'])
@admin_token_required
def get_user_by_id(public_id):
    return jsonify({'user': User.objects(public_id=public_id).first()})


@app.route('/api/user/delete_all', methods=['GET'])
@admin_token_required
def delete_all_users():
    User.drop_collection()
    return jsonify({'users': User.objects})


@app.route('/api/user/delete/', methods=['POST'])
@admin_token_required
def delete_user():
    try:

        content = request.get_json()
        email = content['email']

        User.objects(email=email).delete()

    except Exception as e:
        return jsonify({'code': 400, 'message': str(e)})

    return jsonify({'code': 200, 'message': 'ok'})

@app.route('/api/user/bulk/add', methods = ['POST'])
def bulk_add_users():
    
    try:
        list_of_user = request.get_json()
        user_list = []

        for content in list_of_user:
            
            email = content['email']
            password = content['password']

            new_user = User(public_id=str(uuid.uuid4()), email=email, password=password, registered_serial_numbers=[])
            user_list.append(new_user)
        User.objects.insert(user_list)

    except Exception as e:
        print(str(e))
        return make_response(str(e), 400)

    return jsonify({'code':200, 'message':'ok'})













# -------------------------------     Serial number API endpoints ----------------------------------

@app.route('/api/serial_number/', methods = ['GET'])
@admin_token_required
def get_all_serial_numbers():
    return jsonify({'serial_numbers':SerialNumber.objects[:1000]})

@app.route('/api/serial_number/delete', methods = ['GET'])
@admin_token_required
def delete_all_serial_numbers():
    SerialNumber.drop_collection()
    return jsonify({'serial_numbers':SerialNumber.objects})

@app.route('/api/serial_number/<sn>', methods=["GET"])
@login_token_required
def search_sn(sn):
    serial_object = SerialNumber.objects(value = sn).first()
    if serial_object:
        return make_response(jsonify(serial_object.to_json()), 200)
    else:
        return make_response('', 404)

@app.route('/api/serial_number/add', methods = ['POST'])
@admin_token_required
def add_serial_number(): # Requires a JSON to be sent

    try:
        content = request.get_json()

        value = content['value']
        registration_date = content['registration_date']
        registration_user = content['registration_user']
        product_id = content['product_id']

        SerialNumber.objects.insert(SerialNumber(value = value,
                                             registration_date = registration_date,
                                             registration_user = registration_user,
                                             product_id = product_id))
    except Exception as e:
        return make_response(str(e), 400)

    return jsonify({'code':200, 'message':'ok'})

@app.route('/api/serial_number/bulk/add', methods = ['POST'])
@admin_token_required
def bulk_add_serial_number():
    
    try:
        list_of_sn = request.get_json()
        product_list = []

        for content in list_of_sn:
            

            value = content['value']
            registration_date = content['registration_date']
            registration_user = content['registration_user']
            product_id = content['product_id']

            new_sn = SerialNumber(value = value, registration_date = registration_date,registration_user = registration_user,product_id = product_id)
            product_list.append(new_sn)

        SerialNumber.objects.insert(product_list)


    except Exception as e:
        print(str(e))
        return make_response(str(e), 400)

    return jsonify({'code':200, 'message':'ok'})

@app.route('/api/serial_number/register/', methods = ['POST'])
@login_token_required
def register_serial_number_to_user():
        
    token = None

    if 'x-access-token' not in request.headers:
        return jsonify({'message': 'Token is missing!'})

    try:
        token = request.headers['x-access-token']
        sn_raw = request.get_json()['serial_number']

        product_id = sn_raw[:11]
        serial_number = sn_raw[11:]

        data = jwt.decode(token, app.config['SECRET_KEY'])
        
        sn_object = SerialNumber.objects(product_id = product_id,value = serial_number).first() 

        if sn_object == None:
            return jsonify({'message':'The serial number seems to not be valid'})
        
        #print("SN Object registration user: ", sn_object['registration_user'], " | Length: ", len(sn_object['registration_user']))        


        if len(sn_object['registration_user']) != 0:
            #The serial number has already been registered. Let's check from whom.
            if sn_object['registration_user'] == data['public_id']:
                # The user has already registered this product serial number.            
                return jsonify({'message':'You have already registered this product', 'serial_number':sn_object})
            else:
                return jsonify({'message':'Someone else has already activated this product!'})

        else:

            try:
                # The serial number is ready to be registered
                user_id = data['public_id']
                registration_date = datetime.today().strftime('%Y-%m-%d')
            
                print('Adding the serial number to the user data')
                user = User.objects(public_id = user_id).first()
                user.registered_serial_numbers = user.registered_serial_numbers + [sn_object.value]
                print('About to update...')
                user.save()
                #sn_object.update(registration_user = user_id)
                #sn_object.update(registration_date = registration_date)
                
                print('Done updating.')

            except Exception as e:
                return jsonify({'Exception':str(e)})

            
            return jsonify({'message':'Your product has been registered successfully'})
        #current_user = User.objects(public_id = data['public_id']).first()
        #serial_number = SerialNumber.objects(value = sn_to_register).first()

    except Exception as e:
        return jsonify({'message': 'Token is invalid!', 'exception':str(e)})

    return jsonify({'message':'Unexpected error'})

    

# -------------------------------------------------------------- Products API endpoints -------------------------------------------------------------------



@app.route('/api/product/', methods = ['GET'])
@admin_token_required
def get_all_products():
    return jsonify(Product.objects)

@app.route('/api/product/<product_id>', methods = ['GET'])
@login_token_required
def get_product_by_id(product_id):
    product_object = Product.objects(product_id = product_id).first()
    if product_object:
        return make_response(jsonify(product_object.to_json()), 200)

    return jsonify({'code':404, 'message':"Product not found."})

@app.route('/api/product/add', methods = ['POST'])
@admin_token_required
def insert_new_product():
    try:
        content = request.get_json()
        product_id = content['product_id']
        name = content['name']
        image_url = content['image_url']
        Product.objects.insert(Product(product_id = product_id, name = name, image_url = image_url))

        return jsonify({'code':200, 'message':'ok'})
    except Exception as e:
        return jsonify({'code':400, 'message':str(e)})


@app.route('/api/product/delete/')
@admin_token_required
def delete_all_products():
    Product.drop_collection()
    return jsonify({'products':Product.objects})

@app.route('/api/product/delete/<product_id>')
@admin_token_required
def delete_product(product_id):
    try:
        Product.objects(product_id = product_id).delete()


    except Exception as e:
        return jsonify({'code':400, 'message':str(e)})
    return jsonify({'code':200})

@app.route('/api/user/login/', methods = ['POST'])
def login():

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
        user_expire_session = datetime.utcnow() + timedelta(minutes = 120)

        print('Login successful')
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': user_expire_session}, app.config['SECRET_KEY'])

        token = token.decode('UTF-8')
        return jsonify({'token': token})

    return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route("/", methods=['GET'])
def testing_homepage():
    return "Your container is working"


if __name__ == '__main__':
    # app.run(host = "0.0.0.0", port = 80, debug = False)
    app.run(host="127.0.0.1", port=5000, debug=True)
