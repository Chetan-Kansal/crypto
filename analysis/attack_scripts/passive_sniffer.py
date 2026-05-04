from utils import setup_args, save_log, get_mock_context

args = setup_args("Simulate passive eavesdropping on message transport")
ctx = get_mock_context(args.mode)

print(f"[*] Starting Passive Sniffer on mode: {args.mode}")

if args.mode == "plain_chat":
    observed = ctx.plaintext
    res = "plaintext visible"
    impact = "Critical - Full confidentiality loss"
elif args.mode == "encrypted_chat":
    observed = ctx.ciphertext
    res = "ciphertext only"
    impact = "Low - Confidentiality preserved via AES-GCM"
elif args.mode == "forward_secret_chat":
    observed = ctx.ciphertext + " (with periodic rekey events)"
    res = "ciphertext only"
    impact = "Low - Confidentiality preserved with perfect forward secrecy"

save_log("passive_sniffer", args.mode, observed, res, impact)
