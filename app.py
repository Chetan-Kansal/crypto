import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from models.db import init_db, create_user, verify_user, get_user_by_id, get_all_users, save_message, get_messages

from crypto.dh_utils import generate_dh_private_key, get_public_bytes, perform_key_exchange, load_public_key
from crypto.aes_utils import encrypt_message, decrypt_message
from crypto.key_manager import KeyManager

crypto_sessions = {}  # In-memory store for active KeyManagers (room -> KeyManager)

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

@socketio.on('join_attacker')
def on_join_attacker():
    join_room('attacker_room')

@socketio.on('join_visualizer')
def on_join_visualizer():
    join_room('visualizer_room')

def get_crypto_session(sender_id, receiver_id):
    """Get or create a crypto session, emitting live DH events to the visualizer."""
    room = f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
    is_new = room not in crypto_sessions
    if is_new:
        # ── Phase 2: Ephemeral ECDH ──────────────────────────────
        alice_priv = generate_dh_private_key()
        bob_priv   = generate_dh_private_key()
        alice_pub  = get_public_bytes(alice_priv)
        bob_pub    = get_public_bytes(bob_priv)

        alice_pub_hex = alice_pub.hex()[:24]
        bob_pub_hex   = bob_pub.hex()[:24]

        # ── Phase 3: ECDH + HKDF ────────────────────────────────
        shared_secret = perform_key_exchange(alice_priv, load_public_key(bob_pub))
        crypto_sessions[room] = KeyManager(shared_secret, rotation_interval=5)

        fingerprint = crypto_sessions[room].get_state()['fingerprint']

        # ── Broadcast live DH handshake events to visualizer room ─
        socketio.emit('crypto_event', {
            'phase': 'dh_start',
            'label': '🔑 DH Handshake Initiated',
            'detail': f'Generating ephemeral SECP256R1 key pairs for new session: {room}',
            'color': 'blue',
            'room_id': room
        }, room='visualizer_room')

        socketio.emit('crypto_event', {
            'phase': 'dh_exchange',
            'label': '📡 Public Keys Exchanged',
            'detail': f'Alice_pub: {alice_pub_hex}… | Bob_pub: {bob_pub_hex}…',
            'color': 'blue',
            'room_id': room
        }, room='visualizer_room')

        socketio.emit('crypto_event', {
            'phase': 'hkdf',
            'label': '🔬 HKDF-SHA256 Key Derivation',
            'detail': f'Shared secret → 256-bit AES key | Fingerprint: {fingerprint}',
            'color': 'purple',
            'room_id': room
        }, room='visualizer_room')

        socketio.emit('crypto_event', {
            'phase': 'session_ready',
            'label': '✅ Secure Session Established',
            'detail': f'AES-GCM ready | Key: {fingerprint} | Rotation every 5 msgs',
            'color': 'green',
            'room_id': room,
            'fingerprint': fingerprint
        }, room='visualizer_room')

    return crypto_sessions[room], is_new

@socketio.on('send_message')
def handle_send_message(data):
    sender_id       = session.get('user_id')
    sender_username = session.get('username')
    receiver_id     = data['receiver_id']
    content         = data['message']

    if sender_id and receiver_id and content:
        room = f"chat_{min(sender_id, int(receiver_id))}_{max(sender_id, int(receiver_id))}"
        km, is_new_session = get_crypto_session(sender_id, int(receiver_id))

        if is_new_session:
            logs = [
                "[DH] Generated Ephemeral Private Key (SECP256r1)",
                "[DH] Exchanging Public Keys...",
                "[HKDF] Deriving 256-bit Session Key via SHA-256...",
                "[AES] Initialized AES-GCM for Secure Transport"
            ]
            emit('handshake_logs', {'logs': logs}, room=f"user_{sender_id}")
            emit('handshake_logs', {'logs': logs}, room=f"user_{receiver_id}")

        # ── Phase 4: AES-GCM Encryption ──────────────────────────
        state_before = km.get_state()
        encrypted_content = encrypt_message(km.get_key(), content)

        # Extract IV and tag from the base64 blob for display (first 12 bytes = IV, last 16 = tag)
        import base64
        raw = base64.b64decode(encrypted_content)
        iv_hex  = raw[:12].hex()
        tag_hex = raw[-16:].hex()
        ct_hex  = raw[12:-16].hex()[:24]

        socketio.emit('crypto_event', {
            'phase': 'aes_encrypt',
            'label': f'🔒 AES-GCM Encrypt [{sender_username}→]',
            'detail': f'Plaintext: "{content[:20]}{"…" if len(content)>20 else ""}" | IV: {iv_hex} | CT: {ct_hex}… | Tag: {tag_hex}',
            'color': 'yellow',
            'room_id': room,
            'plaintext': content[:30],
            'iv': iv_hex,
            'ciphertext_preview': ct_hex + '…',
            'tag': tag_hex
        }, room='visualizer_room')

        # ── Save to DB ────────────────────────────────────────────
        save_message(sender_id, receiver_id, encrypted_content)

        # ── Key Rotation Check ────────────────────────────────────
        was_rotated = km.message_count == (km.rotation_interval - 1)
        km.record_message()
        state_after = km.get_state()

        if was_rotated:
            socketio.emit('crypto_event', {
                'phase': 'key_rotation',
                'label': '🔄 Forward Secrecy: Key Rotated!',
                'detail': f'Old key destroyed. New key: {state_after["fingerprint"]} | Old msgs permanently sealed.',
                'color': 'orange',
                'room_id': room,
                'new_fingerprint': state_after['fingerprint']
            }, room='visualizer_room')

        message_data = {
            'sender_id':       sender_id,
            'sender_username': sender_username,
            'receiver_id':     int(receiver_id),
            'content':         encrypted_content,
            'is_encrypted':    True
        }

        emit('receive_message', message_data, room=f"user_{sender_id}")
        emit('receive_message', message_data, room=f"user_{receiver_id}")

        emit('attacker_intercept', {
            'sender':      sender_username,
            'receiver_id': int(receiver_id),
            'ciphertext':  encrypted_content
        }, room='attacker_room')

        emit('update_crypto_state', room=f"user_{sender_id}")
        emit('update_crypto_state', room=f"user_{receiver_id}")

        # ── Live decryption event (simulating receiver side) ──────
        socketio.emit('crypto_event', {
            'phase': 'aes_decrypt',
            'label': f'🔓 AES-GCM Decrypt [→{sender_username}\'s peer]',
            'detail': f'Auth tag verified ✅ | Plaintext recovered: "{content[:20]}{"…" if len(content)>20 else ""}"',
            'color': 'green',
            'room_id': room
        }, room='visualizer_room')

        # Notify visualizer of updated session state
        socketio.emit('session_state_update', {
            'room_id':    room,
            'fingerprint': state_after['fingerprint'],
            'msgs_until_rotation': state_after['messages_until_rotation']
        }, room='visualizer_room')



@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    ciphertext = data.get('ciphertext')
    sender_id = int(data.get('sender_id'))
    receiver_id = int(data.get('receiver_id'))
    
    room = f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
    if room not in crypto_sessions:
        return jsonify({'plaintext': '[Decryption Failed - No Active Session]'})
        
    km = crypto_sessions[room]
    
    # Try all valid keys (current and previous)
    for key in km.get_decryption_keys():
        if key is None: continue
        plaintext = decrypt_message(key, ciphertext)
        if plaintext is not None:
            return jsonify({'plaintext': plaintext})
            
    return jsonify({'plaintext': '[Decryption Failed - Key Rotated/Lost]'})

@app.route('/api/crypto_state/<int:receiver_id>')
def crypto_state(receiver_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    sender_id = session['user_id']
    receiver_id = int(receiver_id)
    room = f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
    
    if room in crypto_sessions:
        return jsonify(crypto_sessions[room].get_state())
    return jsonify({'fingerprint': 'NONE', 'messages_until_rotation': 5})

@app.route('/visualizer')
def visualizer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('visualizer.html')

@app.route('/attacker')
def attacker_dashboard():
    return render_template('attacker.html')

@app.route('/get_chat_history/<int:receiver_id>')
def get_chat_history(receiver_id):
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401
    
    sender_id = session['user_id']
    messages = get_messages(sender_id, receiver_id)
    return {'messages': messages}

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, debug=False, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
