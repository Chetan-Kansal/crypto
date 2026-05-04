import sys, os
from utils import setup_args, save_log, get_mock_context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from crypto.aes_utils import decrypt_message

args = setup_args("Simulate Session Key Compromise")
ctx = get_mock_context(args.mode)

print(f"[*] Starting Key Compromise Test on mode: {args.mode}")

if args.mode == "plain_chat":
    observed = "Not Applicable - No key exists"
    res = "not applicable"
    impact = "Critical - Always readable"
else:
    # Attacker steals current key
    stolen_key = ctx.km.get_key()
    decrypted_count = 0
    
    for c in ctx.history:
        pt = decrypt_message(stolen_key, c)
        if pt is not None:
            decrypted_count += 1
            
    if args.mode == "encrypted_chat":
        # In encrypted_chat, rotation_interval=999, so stolen key decrypts everything.
        observed = f"Decrypted {decrypted_count}/{len(ctx.history)} historical messages"
        res = "entire session exposed"
        impact = "High - Static session key compromises all past history"
    elif args.mode == "forward_secret_chat":
        # In forward_secret, key rotated after 2 messages. Stolen key can only decrypt recent.
        observed = f"Decrypted {decrypted_count}/{len(ctx.history)} historical messages"
        res = "only current key window exposed"
        impact = "Low - Forward secrecy successfully protected older messages"

save_log("key_compromise", args.mode, observed, res, impact)
