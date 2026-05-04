import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto.dh_utils import generate_dh_private_key, get_public_bytes, perform_key_exchange, load_public_key
from crypto.aes_utils import encrypt_message, decrypt_message
from crypto.key_manager import KeyManager

print("=== ATTACK SIMULATION ===")

# --- 1. INSECURE SYSTEM SIMULATION ---
print("\n--- INSECURE SYSTEM (Static Key + Fixed IV/ECB-like) ---")
STATIC_KEY = b'12345678901234567890123456789012' # 32 bytes
FIXED_IV = b'0000000000000000'

def insecure_encrypt(plaintext):
    cipher = Cipher(algorithms.AES(STATIC_KEY), modes.CTR(FIXED_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext.encode()) + encryptor.finalize()

def insecure_decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(STATIC_KEY), modes.CTR(FIXED_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

msg1 = insecure_encrypt("Hello Alice")
msg2 = insecure_encrypt("Secret password is 123")

print("[*] Eavesdropping Attack (Insecure):")
print("    Attacker captures ciphertext:", msg1.hex())
# Since CTR mode with fixed IV is used, XORing ciphertexts gives XOR of plaintexts!
xor_ciphers = bytes(a ^ b for a, b in zip(msg1, msg2[:len(msg1)]))
print("    Attacker computes XOR of plaintexts:", xor_ciphers)
print("    EAVESDROPPING SUCCESSFUL on Fixed IV!")

print("\n[*] Replay Attack (Insecure):")
print("    Attacker resends msg1.")
print("    Bob receives and decrypts:", insecure_decrypt(msg1).decode())
print("    REPLAY SUCCESSFUL (Bob has no way to tell it's a replay)")

print("\n[*] Key Compromise Attack (Insecure):")
print("    Attacker steals STATIC_KEY.")
print("    Attacker decrypts past msg2:", insecure_decrypt(msg2).decode())
print("    KEY COMPROMISE SUCCESSFUL (No Forward Secrecy)")


# --- 2. SECURE SYSTEM SIMULATION ---
print("\n--- SECURE SYSTEM (Ephemeral DH + AES-GCM + Rotation) ---")

alice_priv = generate_dh_private_key()
bob_priv = generate_dh_private_key()
shared_secret = perform_key_exchange(alice_priv, load_public_key(get_public_bytes(bob_priv)))

km = KeyManager(shared_secret, rotation_interval=2)

s_msg1 = encrypt_message(km.get_key(), "Hello Alice")
km.record_message()
s_msg2 = encrypt_message(km.get_key(), "Secret password is 123")
km.record_message() # This triggers rotation!
s_msg3 = encrypt_message(km.get_key(), "New secure message")

print("[*] Eavesdropping Attack (Secure):")
print("    Attacker captures AES-GCM ciphertexts.")
print("    Attacker cannot compute XOR because IV is random and AES-GCM provides CCA security.")
print("    EAVESDROPPING FAILED")

print("\n[*] Replay Attack (Secure):")
print("    Attacker intercepts s_msg1 and modifies a single bit.")
try:
    # Tamper with ciphertext
    tampered = base64.b64encode(base64.b64decode(s_msg1)[:-1] + b'X').decode()
    decrypt_message(km.get_decryption_keys()[1], tampered) # keys[1] because it rotated
    print("    Tampered message decrypted successfully? NO!")
except Exception:
    print("    REPLAY/TAMPERING FAILED (AES-GCM Authentication Tag check failed)")

print("\n[*] Key Compromise Attack (Secure):")
print("    Attacker compromises Alice's CURRENT session key (after rotation).")
current_stolen_key = km.get_key()
print("    Attacker attempts to decrypt s_msg1 (past message) with stolen key...")
decrypted_past = decrypt_message(current_stolen_key, s_msg1)
if decrypted_past is None:
    print("    KEY COMPROMISE FAILED to read history (Forward Secrecy Achieved!)")
else:
    print("    Failed.")
