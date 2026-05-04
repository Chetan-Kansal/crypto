document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    let currentRoom = null;
    let selectedUserId = null;

    const usersList = document.querySelectorAll('.user-item');
    const chatArea = document.getElementById('chat-area');
    const chatWith = document.getElementById('chat-with');
    const messagesContainer = document.getElementById('messages');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    const packetLogs = document.getElementById('packet-logs');
    const keyFingerprint = document.getElementById('key-fingerprint');
    const keyRotationCount = document.getElementById('key-rotation-count');
    const verifyBtn = document.getElementById('verify-btn');

    if (verifyBtn) {
        verifyBtn.addEventListener('click', () => {
            const currentFingerprint = keyFingerprint.textContent;
            if (currentFingerprint !== 'NONE') {
                alert(`🛡️ SAFETY NUMBER VERIFICATION\n\nYour shared Session Fingerprint is:\n[ ${currentFingerprint} ]\n\nCompare this out-of-band with ${chatWith.textContent.replace('Chat with ', '')} to verify no Man-in-the-Middle (MitM) attack is occurring.`);
            } else {
                alert("No active secure session established yet. Send a message to initiate Diffie-Hellman Key Exchange.");
            }
        });
    }

    function updateCryptoState() {
        if (!selectedUserId) return;
        fetch(`/api/crypto_state/${selectedUserId}`)
            .then(res => res.json())
            .then(data => {
                keyFingerprint.textContent = data.fingerprint;
                keyRotationCount.textContent = data.messages_until_rotation;
                
                // Add a visual flash effect to show rotation
                if (data.messages_until_rotation === 5) {
                    keyFingerprint.style.color = '#ff4444';
                    setTimeout(() => keyFingerprint.style.color = '', 1000);
                }
            });
    }

    function logPacket(action, details, isError = false) {
        const li = document.createElement('li');
        li.textContent = `[${new Date().toLocaleTimeString()}] ${action}: ${details}`;
        if (isError) li.style.color = '#ff4444';
        packetLogs.appendChild(li);
        packetLogs.scrollTop = packetLogs.scrollHeight;
    }

    usersList.forEach(item => {
        item.addEventListener('click', () => {
            // Remove active class from all
            usersList.forEach(u => u.classList.remove('active'));
            item.classList.add('active');

            const userId = item.getAttribute('data-id');
            const username = item.getAttribute('data-username');
            
            selectedUserId = parseInt(userId);
            chatWith.textContent = `Chat with ${username}`;
            chatArea.style.display = 'flex';

            // Fetch history
            fetchHistory(selectedUserId);
            updateCryptoState();
        });
    });

    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    function sendMessage() {
        const text = messageInput.value.trim();
        if (text && selectedUserId) {
            logPacket("OUTBOUND", `Plaintext sent to server encryption proxy`);
            socket.emit('send_message', {
                receiver_id: selectedUserId,
                message: text
            });
            messageInput.value = '';
        }
    }

    socket.on('update_crypto_state', () => {
        updateCryptoState();
    });

    socket.on('handshake_logs', (data) => {
        data.logs.forEach(log => {
            logPacket("HANDSHAKE", log);
        });
    });

    socket.on('receive_message', (data) => {
        logPacket("INBOUND (WebSocket)", `Ciphertext: ${data.content.substring(0,20)}...`);
        if (data.sender_id === selectedUserId && data.receiver_id === currentUserId) {
            appendMessage(data.content, false, data.sender_username, true, data.sender_id, data.receiver_id);
        } else if (data.sender_id === currentUserId && data.receiver_id === selectedUserId) {
            appendMessage(data.content, true, data.sender_username, true, data.sender_id, data.receiver_id);
        }
    });

    function fetchHistory(userId) {
        fetch(`/get_chat_history/${userId}`)
            .then(res => res.json())
            .then(data => {
                messagesContainer.innerHTML = '';
                if (data.messages) {
                    data.messages.forEach(msg => {
                        const isSent = msg.sender_id === currentUserId;
                        appendMessage(msg.content, isSent, isSent ? currentUsername : "Them", true, msg.sender_id, msg.receiver_id);
                    });
                }
            });
    }

    function decryptMessage(contentDiv, ciphertext, senderId, receiverId) {
        logPacket("API REQ", `POST /api/decrypt (${ciphertext.substring(0, 15)}...)`);
        fetch('/api/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ciphertext: ciphertext,
                sender_id: senderId,
                receiver_id: receiverId
            })
        })
        .then(res => res.json())
        .then(data => {
            if (data.plaintext) {
                if (data.plaintext.includes("Failed")) {
                    logPacket("API RES (ERROR)", `Decryption failed (Key lost/rotated)`, true);
                    contentDiv.textContent = data.plaintext;
                    contentDiv.style.color = 'red';
                    contentDiv.style.fontStyle = 'italic';
                } else {
                    logPacket("API RES", `Decrypted Plaintext: ${data.plaintext}`);
                    contentDiv.textContent = data.plaintext;
                }
            }
        });
    }

    function appendMessage(content, isSent, senderName, isEncrypted = false, senderId = null, receiverId = null) {
        const div = document.createElement('div');
        div.className = `message ${isSent ? 'sent' : 'received'}`;
        
        const senderDiv = document.createElement('div');
        senderDiv.className = 'message-sender';
        senderDiv.textContent = isSent ? 'You' : senderName;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        
        if (isEncrypted) {
            contentDiv.textContent = "🔒 " + content.substring(0, 15) + "...";
            contentDiv.style.fontFamily = 'monospace';
            decryptMessage(contentDiv, content, senderId, receiverId);
        } else {
            contentDiv.textContent = content;
        }

        div.appendChild(senderDiv);
        div.appendChild(contentDiv);
        
        messagesContainer.appendChild(div);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
});
