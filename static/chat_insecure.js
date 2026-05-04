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
        });
    });

    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    function sendMessage() {
        const text = messageInput.value.trim();
        if (text && selectedUserId) {
            socket.emit('send_message', {
                receiver_id: selectedUserId,
                message: text
            });
            messageInput.value = '';
        }
    }

    socket.on('receive_message', (data) => {
        if (data.sender_id === selectedUserId && data.receiver_id === currentUserId) {
            appendMessage(data.content, false, data.sender_username);
        } else if (data.sender_id === currentUserId && data.receiver_id === selectedUserId) {
            appendMessage(data.content, true, data.sender_username);
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
                        // For history, we don't have the sender_username directly in the message row,
                        // but we can infer it or just not display it for 1-1 chat
                        appendMessage(msg.content, isSent, isSent ? currentUsername : "Them");
                    });
                }
            });
    }

    function appendMessage(content, isSent, senderName) {
        const div = document.createElement('div');
        div.className = `message ${isSent ? 'sent' : 'received'}`;
        
        const senderDiv = document.createElement('div');
        senderDiv.className = 'message-sender';
        senderDiv.textContent = isSent ? 'You' : senderName;
        
        const contentDiv = document.createElement('div');
        contentDiv.textContent = content;

        div.appendChild(senderDiv);
        div.appendChild(contentDiv);
        
        messagesContainer.appendChild(div);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
});
