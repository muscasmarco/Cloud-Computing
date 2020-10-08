from flask import Flask, jsonify, make_response, request
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta
import json
from flask import render_template

app = Flask(__name__)
app.config.from_pyfile('db_config.cfg')
db = MongoEngine(app)

class User(db.Document):
    _id = db.IntField(primary_key = True)
    email = db.StringField(unique = True)
    password = db.StringField() 
    registered_serial_numbers = db.ListField(default = [])

    def to_json(self):
        raw_json = {"email":self.email,
                    "password":self.password,
                    "registered_serial_numbers":self.registered_serial_numbers}
        return raw_json

class Product(db.Document):
    product_id = db.IntField(primary_key = True)
    name = db.StringField(required = True, max_length = 100)
    image_url = db.StringField(required = False)

    def to_json(self):
        raw_json = {'product_id':self.product_id,
                    'name':self.name,
                    'image_url':self.image_url}
        return raw_json

class SerialNumber(db.Document):
    value = db.StringField(required = True, unique = True, primary_key = True)
    registration_date = db.StringField()
    registration_user = db.IntField(required = True) # ID of the registering user
    product = Product()


    def to_json(self):
        raw_json = {'value':self.value, 
                    'registration_date':self.registration_date,
                    'registration_user':self.registration_user,
                    'product':self.registration_user
                    }
        return raw_json




# -------------------------------------------- User API endpoints ---------------------------------- 


@app.route('/api/user/register', methods = ['POST'])
def register():

    request_content = request.get_json()

    try:

        email = request_content['email']
        password = request_content['password']
        
        User.objects.insert(User(email = email, password = password, registered_serial_numbers = []))
    except Exception as e:
        return jsonify({'code':400, 'message':str(e)})

    return make_response('User registered successfully.', 200)


@app.route('/api/user/', methods = ['GET'])
def get_all_users():
    return jsonify({'users':User.objects})

@app.route('/api/user/<user_id>', methods = ['GET'])
def get_user_by_id(user_id):
    return jsonify(User.objects({'email':_id}))

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

@app.route("/", methods = ['GET'])
def testing_homepage():
    return "Your container is working"

if __name__ == '__main__':
    app.run(host = "0.0.0.0", port=80, debug=True)




