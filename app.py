from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import os
# import google.auth.transport.requests
# from google.oauth2 import id_token


app = Flask(__name__)
CORS(app)

MONGODB_URI = os.getenv('MONGODB_URI')
client = MongoClient(MONGODB_URI)
db = client['user_database']
users_collection = db['users']

@app.route('/signup', methods=['POST'])
def handle_signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    profile_pic_url = data.get('profilePic')

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user_data = {
        'name': name,
        'email': email,
        'password': hashed_password,
        'profile_pic':profile_pic_url
    }


    users_collection.insert_one(user_data)

    return jsonify({'success': True, 'message': 'Signup successful'})

@app.route('/login', methods=['POST'])
def handle_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    user = users_collection.find_one({'email': email})

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        user_data = {
            'name': user['name'],
            'email': user['email'],
            'profile_pic' : user['profile_pic']
        }

        return jsonify({'success': True, 'message': 'Login successful', 'user': user_data})
    else:
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401


@app.route('/checkUser', methods=['POST'])
def check_user():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    user = users_collection.find_one({'email': email})

    if user:
        return jsonify({'success': True, 'exists': True, 'message': 'User already exists'})
    else:
        return jsonify({'success': True, 'exists': False, 'message': 'User does not exist'})




if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0")
