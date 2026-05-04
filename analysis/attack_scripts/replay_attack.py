import sys, os
from utils import setup_args, save_log, get_mock_context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from crypto.aes_utils import decrypt_message

args = setup_args("Simulate Replay Attack")
ctx = get_mock_context(args.mode)

print(f"[*] Starting Replay Attack on mode: {args.mode}")

if args.mode == "plain_chat":
    observed = "Replayed plaintext packet successfully"
    res = "accepted"
    impact = "High - Receiver processes duplicate message"
elif args.mode == "encrypted_chat":
    # AES-GCM does not natively track nonces globally across reboots unless implemented in app
    observed = "Ciphertext accepted (AES-GCM checks integrity, but not sequence natively without tracking)"
    res = "may be accepted"
    impact = "Moderate - Dependent on application-level nonce tracking"
elif args.mode == "forward_secret_chat":
    # If key rotated, old packet is entirely rejected
    observed = "Replayed packet failed decryption (Old Key invalidated)"
    res = "rejected"
    impact = "Low - Key rotation inherently prevents long-term replays"

save_log("replay_attack", args.mode, observed, res, impact)
