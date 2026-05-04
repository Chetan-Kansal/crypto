import sys, os, base64
from utils import setup_args, save_log, get_mock_context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from crypto.aes_utils import decrypt_message

args = setup_args("Simulate Message Tampering")
ctx = get_mock_context(args.mode)

print(f"[*] Starting Tamper Attack on mode: {args.mode}")

if args.mode == "plain_chat":
    observed = "Modified plaintext accepted"
    res = "accepted"
    impact = "High - No integrity checks"
else:
    # Tamper with the ciphertext payload (flip last byte of base64)
    tampered_bytes = bytearray(base64.b64decode(ctx.ciphertext))
    tampered_bytes[-1] ^= 0x01
    tampered_b64 = base64.b64encode(tampered_bytes).decode()
    
    pt = decrypt_message(ctx.km.get_key(), tampered_b64)
    if pt is None:
        observed = "AES-GCM Authentication Tag verification failed."
        res = "rejected"
        impact = "Low - Integrity strictly preserved by AES-GCM"
    else:
        observed = "Tampered message accepted"
        res = "accepted"
        impact = "Critical - Cryptography failure"

save_log("tamper_attack", args.mode, observed, res, impact)
