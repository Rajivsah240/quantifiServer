from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import os
from flask_mail import Mail, Message
import random


app = Flask(__name__)
CORS(app)


MAIL_EMAIL = os.getenv('MAIL_EMAIL')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = ('Quantifi', MAIL_EMAIL)
app.config['MAIL_USERNAME'] = MAIL_EMAIL
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD

mail = Mail(app)

MONGODB_URI = os.getenv('MONGODB_URI')
client = MongoClient(MONGODB_URI)
db = client['user_database']
users_collection = db['users']
groups_collection = db['groups']
messages_collection = db['messages']

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
        'profile_pic': profile_pic_url
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
            'profile_pic': user['profile_pic']
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

@app.route('/checkEmail', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email')

    user = users_collection.find_one({'email': email})

    if user:
        otp = ''.join(random.choices('0123456789', k=4))
        users_collection.update_one({'email': email}, {'$set': {'otp': otp}})

        msg = Message('OTP Verification', recipients=[email])
        msg.html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
        }}
        .container {{
            max-width: 600px;
            margin: auto;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            text-align: center;
            padding: 10px 0;
            border-bottom: 1px solid #e0e0e0;
        }}
        .otp {{
            font-size: 24px;
            color: #333333;
            font-weight: bold;
            margin: 20px 0;
            text-align: center;
        }}
        .message {{
            font-size: 18px;
            color: #555555;
            text-align: center;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Quantifi</h1>
        </div>
        <div class="message">
            Your OTP for password reset is:
        </div>
        <div class="otp">{otp}</div>
        <div class="message">
            Please use this OTP to reset your password.
        </div>
    </div>
</body>
</html>
"""
        mail.send(msg)

        return jsonify({'success': True, 'message': 'Email exists'})
    else:
        return jsonify({'success': False, 'message': 'Email does not exist'})

@app.route('/verifyOTP', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    user = users_collection.find_one({'email': email, 'otp': otp})

    if user:
        users_collection.update_one({'email': email}, {'$unset': {'otp': ""}})

        return jsonify({'success': True, 'message': 'OTP verified'})
    else:
        return jsonify({'success': False, 'message': 'Invalid OTP'})

@app.route('/resetPassword', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('newPassword')

    if not new_password:
        return jsonify({'success': False, 'message': 'Password is required'}), 400

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})

    return jsonify({'success': True, 'message': 'Password has been reset successfully'})

@app.route('/user-groups', methods=['GET'])
def get_user_groups():
    email = request.args.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    group_ids = user.get('groups', [])
    groups = groups_collection.find({'group_id': {'$in': group_ids}})
    group_list = [{'id': group['group_id'], 'name': group['group_name']} for group in groups]

    return jsonify({'success': True, 'groups': group_list})

@app.route('/create-group', methods=['POST'])
def create_group():
    data = request.get_json()
    group_name = data.get('groupName')
    user_email = data.get('userEmail')

    if not group_name or not user_email:
        return jsonify({'success': False, 'message': 'Group name and user email are required'}), 400

    group_id = str(random.randint(100000, 999999))
    groups_collection.insert_one({'group_id': group_id, 'group_name': group_name, 'members': [user_email]})
    users_collection.update_one({'email': user_email}, {'$push': {'groups': group_id}})

    return jsonify({'success': True, 'group_id': group_id})

@app.route('/join-group', methods=['POST'])
def join_group():
    data = request.get_json()
    group_id = data.get('groupId')
    user_email = data.get('userEmail')

    if not group_id or not user_email:
        return jsonify({'success': False, 'message': 'Group ID and user email are required'}), 400

    group = groups_collection.find_one({'group_id': group_id})

    if group:
        if user_email not in group['members']:
            groups_collection.update_one({'group_id': group_id}, {'$push': {'members': user_email}})
            users_collection.update_one({'email': user_email}, {'$push': {'groups': group_id}})
        return jsonify({'success': True, 'message': 'Joined group successfully'})
    else:
        return jsonify({'success': False, 'message': 'Group not found'}), 404

@app.route('/messages', methods=['GET'])
def get_messages():
    group_id = request.args.get('groupId')

    if not group_id:
        return jsonify({'success': False, 'message': 'Group ID is required'}), 400

    messages = db.messages.find({'group_id': group_id})
    message_list = [{'userEmail': msg['user_email'], 'username': msg['username'], 'message': msg['message']} for msg in messages]

    return jsonify({'success': True, 'messages': message_list})

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')
