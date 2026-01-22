from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import datetime
import os
from functools import wraps
from supabase import create_client, Client
import uuid

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Supabase Configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            token = token.split()[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# User Registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = data.get('user_id')
    name = data.get('name')
    password = data.get('password')
    
    if not all([user_id, name, password]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user exists
    existing = supabase.table('users').select('*').eq('user_id', user_id).execute()
    if existing.data:
        return jsonify({'error': 'User ID already exists'}), 400
    
    # Create user
    try:
        supabase.table('users').insert({
            'user_id': user_id,
            'name': name,
            'password_hash': generate_password_hash(password)
        }).execute()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')
    
    # Get user
    result = supabase.table('users').select('*').eq('user_id', user_id).execute()
    
    if not result.data:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user = result.data[0]
    if not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    token = jwt.encode({
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'user': {'user_id': user_id, 'name': user['name']}
    }), 200

# Get all users
@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    result = supabase.table('users').select('user_id, name').neq('user_id', current_user).execute()
    return jsonify(result.data), 200

# Send message
@app.route('/api/messages', methods=['POST'])
@token_required
def send_message(current_user):
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    if not all([receiver_id, content]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if receiver exists
    receiver = supabase.table('users').select('*').eq('user_id', receiver_id).execute()
    if not receiver.data:
        return jsonify({'error': 'Receiver not found'}), 404
    
    # Insert message
    try:
        result = supabase.table('messages').insert({
            'sender_id': current_user,
            'receiver_id': receiver_id,
            'content': content,
            'type': 'text'
        }).execute()
        return jsonify(result.data[0]), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Upload file
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    receiver_id = request.form.get('receiver_id')
    
    if not receiver_id:
        return jsonify({'error': 'Receiver ID required'}), 400
    
    # Check receiver exists
    receiver = supabase.table('users').select('*').eq('user_id', receiver_id).execute()
    if not receiver.data:
        return jsonify({'error': 'Invalid receiver'}), 400
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Generate unique filename
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        # Upload to Supabase Storage
        file_bytes = file.read()
        supabase.storage.from_('chat-files').upload(
            unique_filename,
            file_bytes,
            {'content-type': file.content_type}
        )
        
        # Get public URL
        file_url = supabase.storage.from_('chat-files').get_public_url(unique_filename)
        
        # Insert file record
        file_result = supabase.table('files').insert({
            'filename': filename,
            'file_url': file_url,
            'sender_id': current_user,
            'receiver_id': receiver_id
        }).execute()
        
        # Insert message with file
        message_result = supabase.table('messages').insert({
            'sender_id': current_user,
            'receiver_id': receiver_id,
            'content': filename,
            'type': 'file',
            'file_id': file_result.data[0]['id']
        }).execute()
        
        return jsonify(message_result.data[0]), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get messages between two users
@app.route('/api/messages/<receiver_id>', methods=['GET'])
@token_required
def get_messages(current_user, receiver_id):
    # Get messages where current user is sender or receiver
    result = supabase.table('messages').select('*').or_(
        f'and(sender_id.eq.{current_user},receiver_id.eq.{receiver_id}),'
        f'and(sender_id.eq.{receiver_id},receiver_id.eq.{current_user})'
    ).order('timestamp', desc=False).execute()
    
    return jsonify(result.data), 200

# Get all conversations
@app.route('/api/conversations', methods=['GET'])
@token_required
def get_conversations(current_user):
    # Get all messages involving current user
    result = supabase.table('messages').select('*').or_(
        f'sender_id.eq.{current_user},receiver_id.eq.{current_user}'
    ).order('timestamp', desc=True).execute()
    
    # Process conversations
    conversations = {}
    for msg in result.data:
        other_user = msg['receiver_id'] if msg['sender_id'] == current_user else msg['sender_id']
        
        if other_user not in conversations:
            # Get user details
            user_result = supabase.table('users').select('name').eq('user_id', other_user).execute()
            if user_result.data:
                conversations[other_user] = {
                    'user_id': other_user,
                    'name': user_result.data[0]['name'],
                    'last_message': msg['content'],
                    'timestamp': msg['timestamp']
                }
    
    return jsonify(list(conversations.values())), 200

# Backup endpoint
@app.route('/api/backup', methods=['GET'])
@token_required
def backup_data(current_user):
    # Get all messages
    messages = supabase.table('messages').select('*').or_(
        f'sender_id.eq.{current_user},receiver_id.eq.{current_user}'
    ).execute()
    
    # Get all files
    files = supabase.table('files').select('*').or_(
        f'sender_id.eq.{current_user},receiver_id.eq.{current_user}'
    ).execute()
    
    return jsonify({
        'messages': messages.data,
        'files': files.data
    }), 200

# Health check
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))