import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from models.db import init_db, create_user, verify_user, get_user_by_id, get_all_users, save_message, get_messages

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# Initialize database
with app.app_context():
    init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if create_user(username, password):
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('chat'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    users = get_all_users(exclude_id=session['user_id'])
    return render_template('chat.html', current_user=session['username'], users=users)

@socketio.on('join')
def on_join(data):
    # Fallback/Backward compatibility or unused now, but let's keep personal room join here
    if 'user_id' in session:
        join_room(f"user_{session['user_id']}")

@socketio.on('connect')
def on_connect():
    if 'user_id' in session:
        join_room(f"user_{session['user_id']}")

@socketio.on('leave')
def on_leave(data):
    username = session.get('username')
    room = data['room']
    leave_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = session.get('user_id')
    sender_username = session.get('username')
    receiver_id = data['receiver_id']
    content = data['message']
    
    if sender_id and receiver_id and content:
        # Save to database (Plaintext for Phase 1)
        save_message(sender_id, receiver_id, content)
        
        message_data = {
            'sender_id': sender_id,
            'sender_username': sender_username,
            'receiver_id': int(receiver_id),
            'content': content
        }
        
        # Broadcast to both sender and receiver personal rooms
        emit('receive_message', message_data, room=f"user_{sender_id}")
        emit('receive_message', message_data, room=f"user_{receiver_id}")

@app.route('/get_chat_history/<int:receiver_id>')
def get_chat_history(receiver_id):
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401
    
    sender_id = session['user_id']
    messages = get_messages(sender_id, receiver_id)
    return {'messages': messages}

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
