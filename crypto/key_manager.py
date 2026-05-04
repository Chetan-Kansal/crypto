import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_session_key(shared_secret, salt=None):
    """Derives a strong session key using HKDF and SHA-256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',
    )
    return hkdf.derive(shared_secret)

class KeyManager:
    """Manages session keys and implements Forward Secrecy via Key Rotation."""
    def __init__(self, dh_shared_secret, rotation_interval=5):
        # Step 3 Compliance: take DH shared secret, derive 256-bit AES key using HKDF + SHA-256
        self.current_key = derive_session_key(dh_shared_secret)
        self.previous_key = None
        self.message_count = 0
        self.rotation_interval = rotation_interval

    def get_key(self):
        return self.current_key
        
    def get_decryption_keys(self):
        return [self.current_key, self.previous_key]

    def get_state(self):
        """Returns visual state of the key manager for the frontend."""
        fingerprint = hashlib.sha256(self.current_key).hexdigest()[:12].upper()
        return {
            'fingerprint': fingerprint,
            'messages_until_rotation': self.rotation_interval - self.message_count
        }

    def record_message(self):
        """Advances the message counter and triggers rotation if threshold met."""
        self.message_count += 1
        if self.message_count >= self.rotation_interval:
            self.rotate_key()

    def rotate_key(self):
        """
        Derives a completely new session key from the current one using HKDF.
        Retains only the immediate previous key for in-flight messages.
        Older keys are discarded, providing Forward Secrecy.
        """
        self.previous_key = self.current_key
        self.current_key = derive_session_key(self.current_key, salt=b'key_rotation')
        self.message_count = 0
