import argparse
import json
import os
import time
import sys

def setup_args(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--mode', choices=['plain_chat', 'encrypted_chat', 'forward_secret_chat'], 
                        required=True, help='Which version of the system to attack')
    return parser.parse_args()

def save_log(attack_name, mode, observed_data, result, security_impact):
    log_data = {
        "timestamp": time.time(),
        "attack_name": attack_name,
        "mode": mode,
        "observed_data": observed_data,
        "result": result,
        "security_impact": security_impact
    }
    
    # Write to correct output directory
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), f"../attack_results/{mode}"))
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"{attack_name}.json")
    
    with open(out_file, "w") as f:
        json.dump(log_data, f, indent=4)
        
    print(f"[*] Saved structured JSON log to: {out_file}")
    print(f"[*] Result: {result}")
    return log_data

# Mocking the crypto context for the simulation
def get_mock_context(mode):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
    from crypto.dh_utils import generate_dh_private_key, get_public_bytes, perform_key_exchange, load_public_key
    from crypto.aes_utils import encrypt_message, decrypt_message
    from crypto.key_manager import KeyManager, derive_session_key
    
    class Context:
        def __init__(self):
            self.mode = mode
            self.plaintext = "Hello Top Secret Project"
            
            # Encrypted variants setup
            self.alice_priv = generate_dh_private_key()
            self.bob_priv = generate_dh_private_key()
            self.shared = perform_key_exchange(self.alice_priv, load_public_key(get_public_bytes(self.bob_priv)))
            self.km = KeyManager(self.shared, rotation_interval=2 if mode == 'forward_secret_chat' else 999)
            
            # Static key for V2 representation if needed, but we use KeyManager with high interval for V2
            self.ciphertext = encrypt_message(self.km.get_key(), self.plaintext)
            
            # Generate history
            self.history = []
            if mode != 'plain_chat':
                self.history.append(encrypt_message(self.km.get_key(), "Msg 1"))
                self.km.record_message()
                self.history.append(encrypt_message(self.km.get_key(), "Msg 2"))
                self.km.record_message()
                self.history.append(encrypt_message(self.km.get_key(), "Msg 3"))
    return Context()
