import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

def encrypt_message(key, plaintext):
    """Encrypts a plaintext message using AES-GCM with a unique ephemeral IV."""
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96-bit IV recommended for AES-GCM
    # Encrypt returns ciphertext + 16-byte authentication tag
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    
    # Prepend IV to ciphertext for storage/transmission
    payload = iv + ciphertext_and_tag
    return base64.b64encode(payload).decode('utf-8')

def decrypt_message(key, encrypted_payload):
    """Decrypts an AES-GCM encrypted payload, verifying integrity automatically."""
    try:
        payload = base64.b64decode(encrypted_payload)
        iv = payload[:12]
        ciphertext_and_tag = payload[12:]
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        return None  # Decryption or authentication failed
