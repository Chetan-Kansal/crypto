from utils import setup_args, save_log, get_mock_context

args = setup_args("Simulate database leak")
ctx = get_mock_context(args.mode)

print(f"[*] Starting DB Leak Test on mode: {args.mode}")

if args.mode == "plain_chat":
    observed = [ctx.plaintext] * 3
    res = "full chat history exposed"
    impact = "Critical - All past data leaked"
elif args.mode == "encrypted_chat":
    observed = ctx.history
    res = "ciphertext only"
    impact = "Moderate - Ciphertexts leaked, but secure unless static key compromised"
elif args.mode == "forward_secret_chat":
    observed = ctx.history
    res = "ciphertext only"
    impact = "Low - Ciphertexts leaked, securely unreadable without ephemeral keys"

save_log("db_leak", args.mode, str(observed), res, impact)
