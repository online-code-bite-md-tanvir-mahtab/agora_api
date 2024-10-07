from flask import Flask,  request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from agora_token_builder import RtcTokenBuilder
import time
import os

app = Flask(__name__)

# Agora credentials
APP_ID = '3f8b6c06334e48ebae82b96e849a62ab'
APP_CERTIFICATE = 'ae2545b63db7412b8dabe0578a388a6c'

# Configure the SQLAlchemy part of the app
app.config['SQLALCHEMY_DATABASE_URI'] =  os.getenv("DATABASE_URL","sqlite:///users.db") # Change to your preferred DB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize the database
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)  # Unique public ID
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Hashed password


class CallSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caller_id = db.Column(db.String(50), nullable=False)
    receiver_id = db.Column(db.String(50), nullable=False)
    channel_name = db.Column(db.String(50), nullable=False)
    receiver_token = db.Column(db.String(250), nullable=False)


with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return "Hello the api is on lets perty...."



@app.route('/delete-call-session', methods=['DELETE'])
def delete_call_session():
    data = request.get_json()

    receiver_id = data.get('receiver_id')

    if not receiver_id:
        return jsonify({'error': 'Receiver ID is required'}), 400

    try:
        # Find the call session by receiver_id
        call_session = CallSession.query.filter_by(receiver_id=receiver_id).first()

        if not call_session:
            return jsonify({'error': 'No active call session found for this receiver'}), 404

        # Delete the call session
        db.session.delete(call_session)
        db.session.commit()

        return jsonify({'message': 'Call session deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# API to send call details to the receiver
@app.route('/send-call-details', methods=['POST'])
def send_call_details():
    data = request.get_json()

    caller_id = data.get('caller_id')
    receiver_id = data.get('receiver_id')
    channel_name = data.get('channel_name')
    receiver_token = data.get('receiver_token')

    if not all([caller_id, receiver_id, channel_name, receiver_token]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Save call session to the database
        call_session = CallSession(
            caller_id=caller_id,
            receiver_id=receiver_id,
            channel_name=channel_name,
            receiver_token=receiver_token
        )
        db.session.add(call_session)
        db.session.commit()

        # Notify the receiver here (Optional, implement WebSocket or Push Notification if needed)

        return jsonify({'message': 'Call details sent successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/check-incoming-call/<receiver_id>', methods=['GET'])
def check_incoming_call(receiver_id):
    # Query the database for an active call session for the given receiver
    call_session = CallSession.query.filter_by(receiver_id=receiver_id).first()

    if call_session:
        return jsonify({
            'caller_id': call_session.caller_id,
            'channel_name': call_session.channel_name,
            'receiver_token': call_session.receiver_token
        }), 200
    else:
        return jsonify({'message': 'No incoming calls'}), 200


# Register user route
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()  # Get JSON data from request
    
    # Check if username or email already exists
    if User.query.filter_by(username=data['username']).first() is not None:
        return jsonify({'message': 'Username already exists'}), 400
    if User.query.filter_by(email=data['email']).first() is not None:
        return jsonify({'message': 'Email already exists'}), 400

    # Create a new user# Replace the hash method from 'sha256' to 'pbkdf2:sha256'
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_password)
    with app.app_context():
        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Login route (Optional)
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Login successful', 'public_id': user.public_id}), 200
    
    return jsonify({'message': 'Invalid username or password'}), 401


# Get all users route
@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()  # Query all users from the database
    output = []

    # Iterate through the users and format the response
    for user in users:
        user_data = {
            'public_id': user.public_id,
            'username': user.username,
            'email': user.email
        }
        output.append(user_data)

    return jsonify({'users': output}), 200


# Function to generate Agora token
def generate_agora_token(channel_name, uid):
    expiration_time_in_seconds = 3600  # Token expiration time in seconds (e.g., 1 hour)
    current_timestamp = int(time.time())
    privilege_expired_ts = current_timestamp + expiration_time_in_seconds

    # Agora roles: Publisher (for broadcasting) or Subscriber
    role = 1  # RtcRole.PUBLISHER

    # Generate token
    token = RtcTokenBuilder.buildTokenWithUid(APP_ID, APP_CERTIFICATE, channel_name, uid, role, privilege_expired_ts)
    return token

@app.route('/generate-token', methods=['GET'])
def get_token():
    # Get the user who initiated the call and the person they want to call
    caller_id = request.args.get('callerId')
    receiver_id = request.args.get('receiverId')
    channel_name = request.args.get("channelname")

    if not caller_id or not receiver_id:
        return jsonify({'error': 'Caller and receiver IDs are required'}), 400



    try:
        # Generate tokens for both caller and receiver
        token_caller = generate_agora_token(channel_name, int(caller_id))
        token_receiver = generate_agora_token(channel_name, int(receiver_id))

        # Return both tokens and the shared channel name
        return jsonify({
            'channelName': channel_name,
            'callerToken': token_caller,
            'receiverToken': token_receiver
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


