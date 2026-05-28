import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from models.db import init_db, create_user, verify_user, get_user_by_id, get_all_users, save_message, get_messages

from crypto.dh_utils import generate_dh_private_key, get_public_bytes, perform_key_exchange, load_public_key
from crypto.aes_utils import encrypt_message, decrypt_message
from crypto.key_manager import KeyManager

# ==========================================
# 🔐 CRYPTOCHAT - SIMPLIFIED PRESENTATION VERSION
# ==========================================
# This file contains the exact same secure chat logic as app.py, 
# but all the complex "visualizer" and "attacker" SocketIO events 
# have been removed to make the code easier to read and present.

crypto_sessions = {}  # In-memory store: Room ID -> KeyManager

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# Initialize database
with app.app_context():
    init_db()

# ==========================================
# 1. STANDARD WEB ROUTES (Login/Register)
# ==========================================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if create_user(request.form['username'], request.form['password']):
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        flash('Username already exists.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = verify_user(request.form['username'], request.form['password'])
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('chat'))
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

# ==========================================
# 2. WEBSOCKET CONNECTION MANAGEMENT
# ==========================================

@socketio.on('connect')
def on_connect():
    if 'user_id' in session:
        # Every user joins their own private notification room
        join_room(f"user_{session['user_id']}")

@socketio.on('join')
def on_join(data):
    if 'user_id' in session:
        join_room(f"user_{session['user_id']}")

@socketio.on('leave')
def on_leave(data):
    leave_room(data['room'])

# ==========================================
# 3. CORE CRYPTOGRAPHIC LOGIC
# ==========================================

def get_crypto_session(sender_id, receiver_id):
    """
    Handles the Diffie-Hellman Key Exchange (ECDH).
    Called before sending a message to ensure a secure session exists.
    """
    room = f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
    is_new = room not in crypto_sessions
    
    if is_new:
        # ── Step 1: Ephemeral Key Generation ──
        # Generate fresh, temporary private keys for both users
        alice_priv = generate_dh_private_key()
        bob_priv   = generate_dh_private_key()
        
        # ── Step 2: Public Key Extraction ──
        # Get the public keys that would normally be sent over the network
        alice_pub  = get_public_bytes(alice_priv)
        bob_pub    = get_public_bytes(bob_priv)

        # ── Step 3: Shared Secret Computation ──
        # ECDH math: Both parties independently arrive at the exact same shared secret!
        shared_secret = perform_key_exchange(alice_priv, load_public_key(bob_pub))
        
        # ── Step 4: Key Derivation (HKDF) ──
        # We don't use the shared secret directly. We put it through HKDF to generate
        # a strong 256-bit AES key. The KeyManager also handles Forward Secrecy (Key Rotation).
        crypto_sessions[room] = KeyManager(shared_secret, rotation_interval=5)

    return crypto_sessions[room], is_new

@socketio.on('send_message')
def handle_send_message(data):
    """
    Triggered when a user clicks 'Send'. Handles Encryption and Forwarding.
    """
    sender_id       = session.get('user_id')
    receiver_id     = data['receiver_id']
    content         = data['message']

    if sender_id and receiver_id and content:
        # 1. Establish or get the current Cryptographic Session
        km, is_new_session = get_crypto_session(sender_id, int(receiver_id))

        if is_new_session:
            # Send initial handshake logs to the UI
            logs = [
                "[DH] Generated Ephemeral Private Key (SECP256r1)",
                "[DH] Exchanging Public Keys...",
                "[HKDF] Deriving 256-bit Session Key via SHA-256...",
                "[AES] Initialized AES-GCM for Secure Transport"
            ]
            emit('handshake_logs', {'logs': logs}, room=f"user_{sender_id}")
            emit('handshake_logs', {'logs': logs}, room=f"user_{receiver_id}")

        # 2. Encrypt the plaintext using AES-256-GCM
        # Notice how the server never logs the plaintext!
        encrypted_content = encrypt_message(km.get_key(), content)

        # 3. Store only the ciphertext in the database
        save_message(sender_id, receiver_id, encrypted_content)

        # 4. Forward Secrecy check
        # This ticks up the message counter. If we hit 5, the KeyManager 
        # destroys the current key and generates a new one automatically.
        km.record_message()

        # 5. Broadcast the encrypted message to both the sender and receiver
        message_data = {
            'sender_id':       sender_id,
            'sender_username': session.get('username'),
            'receiver_id':     int(receiver_id),
            'content':         encrypted_content,
            'is_encrypted':    True
        }
        emit('receive_message', message_data, room=f"user_{sender_id}")
        emit('receive_message', message_data, room=f"user_{receiver_id}")

        # 6. Tell UI to update its security badge (fingerprint)
        emit('update_crypto_state', room=f"user_{sender_id}")
        emit('update_crypto_state', room=f"user_{receiver_id}")

# ==========================================
# 4. DECRYPTION API (Simulating the Client)
# ==========================================

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """
    Normally, decryption happens locally on the user's phone/browser.
    Here, the client asks the server's KeyManager to decrypt it.
    """
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    ciphertext = data.get('ciphertext')
    sender_id = int(data.get('sender_id'))
    receiver_id = int(data.get('receiver_id'))
    
    room = f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
    if room not in crypto_sessions:
        return jsonify({'plaintext': '[Decryption Failed - No Active Session]'})
        
    km = crypto_sessions[room]
    
    # Try all valid keys in the KeyManager window
    # If the key was rotated away long ago, decryption will fail! (Forward Secrecy)
    for key in km.get_decryption_keys():
        if key is None: continue
        plaintext = decrypt_message(key, ciphertext)
        if plaintext is not None:
            return jsonify({'plaintext': plaintext})
            
    return jsonify({'plaintext': '[Decryption Failed - Key Rotated/Lost]'})

# ==========================================
# 5. HELPER ROUTES
# ==========================================

@app.route('/api/crypto_state/<int:receiver_id>')
def crypto_state(receiver_id):
    """Returns the current Key Fingerprint for the Security Badge"""
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    
    sender_id = session['user_id']
    room = f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
    
    if room in crypto_sessions:
        return jsonify(crypto_sessions[room].get_state())
    return jsonify({'fingerprint': 'NONE', 'messages_until_rotation': 5})

@app.route('/get_chat_history/<int:receiver_id>')
def get_chat_history(receiver_id):
    if 'user_id' not in session: return {'error': 'Unauthorized'}, 401
    messages = get_messages(session['user_id'], receiver_id)
    return {'messages': messages}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, debug=False, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
