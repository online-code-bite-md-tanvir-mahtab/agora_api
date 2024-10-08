import logging
import uuid
import time
import os
import pandas as pd
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from agora_token_builder import RtcTokenBuilder

app = Flask(__name__)

# Agora credentials
APP_ID = '3f8b6c06334e48ebae82b96e849a62ab'
APP_CERTIFICATE = 'ae2545b63db7412b8dabe0578a388a6c'

# File paths for storing users and call sessions
USER_CSV = "users.csv"
CALL_SESSION_CSV = "call_sessions.csv"

# Ensure CSV files exist and create them with headers if not
if not os.path.exists(USER_CSV):
    pd.DataFrame(columns=['public_id', 'username', 'email', 'password']).to_csv(USER_CSV, index=False)

if not os.path.exists(CALL_SESSION_CSV):
    pd.DataFrame(columns=['caller_id', 'receiver_id', 'channel_name', 'receiver_token']).to_csv(CALL_SESSION_CSV, index=False)

# Helper functions to read/write CSV files
def load_users():
    return pd.read_csv(USER_CSV)

def save_users(df):
    df.to_csv(USER_CSV, index=False)

def load_call_sessions():
    return pd.read_csv(CALL_SESSION_CSV)

def save_call_sessions(df):
    df.to_csv(CALL_SESSION_CSV, index=False)


@app.route("/")
def home():
    return "Hello the API is on! Let's party..."

@app.route('/delete-call-session', methods=['DELETE'])
def delete_call_session():
    data = request.get_json()
    receiver_id = data.get('receiver_id')

    if not receiver_id:
        return jsonify({'error': 'Receiver ID is required'}), 400

    try:
        df = load_call_sessions()
        if receiver_id in df['receiver_id'].values:
            df = df[df['receiver_id'] != receiver_id]
            save_call_sessions(df)
            return jsonify({'message': 'Call session deleted successfully'}), 200
        else:
            return jsonify({'error': 'No active call session found for this receiver'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        df = load_call_sessions()
        df = df.append({
            'caller_id': caller_id,
            'receiver_id': receiver_id,
            'channel_name': channel_name,
            'receiver_token': receiver_token
        }, ignore_index=True)
        save_call_sessions(df)
        return jsonify({'message': 'Call details sent successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/check-incoming-call/<receiver_id>', methods=['GET'])
def check_incoming_call(receiver_id):
    df = load_call_sessions()
    call_session = df[df['receiver_id'] == receiver_id]

    if not call_session.empty:
        call_session = call_session.iloc[0]
        return jsonify({
            'caller_id': call_session['caller_id'],
            'channel_name': call_session['channel_name'],
            'receiver_token': call_session['receiver_token']
        }), 200
    else:
        return jsonify({'message': 'No incoming calls'}), 200


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    df = load_users()

    if data['username'] in df['username'].values:
        return jsonify({'message': 'Username already exists'}), 400
    if data['email'] in df['email'].values:
        return jsonify({'message': 'Email already exists'}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = {
        'public_id': str(uuid.uuid4()),
        'username': data['username'],
        'email': data['email'],
        'password': hashed_password
    }

    df = df.append(new_user, ignore_index=True)
    save_users(df)

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    df = load_users()

    user = df[df['username'] == data['username']].iloc[0] if not df[df['username'] == data['username']].empty else None

    if user is not None and check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Login successful', 'public_id': user['public_id']}), 200
    return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/users', methods=['GET'])
def get_all_users():
    df = load_users()
    output = df[['public_id', 'username', 'email']].to_dict(orient='records')
    return jsonify({'users': output}), 200


# Function to generate Agora token
def generate_agora_token(channel_name, uid):
    expiration_time_in_seconds = 3600
    current_timestamp = int(time.time())
    privilege_expired_ts = current_timestamp + expiration_time_in_seconds
    role = 1  # RtcRole.PUBLISHER
    token = RtcTokenBuilder.buildTokenWithUid(APP_ID, APP_CERTIFICATE, channel_name, uid, role, privilege_expired_ts)
    return token


@app.route('/generate-token', methods=['GET'])
def get_token():
    caller_id = request.args.get('callerId')
    receiver_id = request.args.get('receiverId')
    channel_name = request.args.get("channelname")

    if not caller_id or not receiver_id:
        return jsonify({'error': 'Caller and receiver IDs are required'}), 400

    try:
        token_caller = generate_agora_token(channel_name, int(caller_id))
        token_receiver = generate_agora_token(channel_name, int(receiver_id))
        return jsonify({
            'channelName': channel_name,
            'callerToken': token_caller,
            'receiverToken': token_receiver
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
