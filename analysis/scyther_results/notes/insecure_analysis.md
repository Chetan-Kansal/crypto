# Formal Analysis: Insecure Protocol

## Protocol Purpose
This model establishes a weak, baseline protocol (`InsecureChat`) that relies exclusively on a static symmetric key `K` shared between `I` (Alice) and `R` (Bob) without any form of freshness (no nonces, no sequence numbers).

## Claims Tested
1. `Secret msg`: Does the message remain confidential?
2. `Alive`: Is the other party active?
3. `Weakagree`: Do both parties agree they communicated with each other?
4. `Nisynch`: Is the protocol resistant to message replays and does it guarantee message ordering?

## Results & Attacks Found

### 1. `Nisynch` FAILED (Replay Attack)
* **Why it fails**: Because there is no freshness token (Nonce or Timestamp) included in the ciphertexts, an adversary can record `{msg}K` from Alice and resend it to Bob infinitely.
* **Attack Trace**: 
  1. `I` sends `{msg}K` intended for `R`.
  2. Adversary intercepts `{msg}K`.
  3. Adversary later replays `{msg}K` to `R`. 
  4. `R` accepts the message as valid because the static key decryption succeeds.

### 2. `Secret` PASSED (Conditionally)
* **Why it passes**: Scyther symbolically assumes `K` is perfectly secret unless explicitly compromised. Since `K` is not leaked in the protocol definition, the message remains confidential. However, as proven in our Python `db_leak_test.py`, if `K` is ever compromised in real life, this guarantee collapses immediately.

## Comparison to Implementation
This formally proves that our "Version 1" system, if secured only by a static AES key (like many amateur systems), would be trivially vulnerable to Replay Attacks in transit, directly validating the need for the ephemeral sessions built in Version 3.
