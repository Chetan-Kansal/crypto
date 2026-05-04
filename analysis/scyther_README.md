# Formal Protocol Verification using Scyther

This directory contains the formal symbolic verification of the chat system's cryptographic protocols. We model and verify two distinct versions of the protocol using the Scyther tool.

## Prerequisites
To run these verifications locally, you must install the Scyther tool:
1. Download Scyther from: [http://people.irisa.fr/Cas.Cremers/scyther/](http://people.irisa.fr/Cas.Cremers/scyther/)
2. Requires Python and Graphviz for rendering attack graphs.

## Protocols Modeled

### 1. `insecure_protocol.spdl`
- **What it represents**: The baseline "Version 1" system, lacking forward secrecy and using static keys without nonces.
- **Expected Output**: Scyther explicitly fails `Nisynch` (Replay attacks) and `Weakagree`, proving the protocol is vulnerable to replay and impersonation.

### 2. `secure_protocol.spdl`
- **What it represents**: The final "Version 3" forward-secret chat. It abstracts the Ephemeral Diffie-Hellman exchange and HKDF key derivation using symbolic nonces and public key authentication to establish a fresh `SessionKey`.
- **Expected Output**: Scyther validates all claims (`Secret`, `Alive`, `Weakagree`, `Nisynch`), proving the protocol guarantees confidentiality, mutual authentication, and replay resistance.

## How to Run the Verification
1. Open the Scyther GUI (`scyther-gui.py`).
2. Click **File -> Open** and select `insecure_protocol.spdl`.
3. Click **Verify -> Verify Protocol**.
4. Observe the red failures. Click on a failed claim to view the generated attack graph showing exactly how an adversary replays or intercepts the message.
5. Repeat the process for `secure_protocol.spdl` and observe the green successful validations.

## Artifacts in this Directory
- `scyther_results/notes/`: Contains written analysis of why the claims failed/passed.
- `scyther_results/screenshots/`: Reserved for UI screenshots of the Scyther output for the final paper.
- `scyther_results/traces/`: Reserved for exported attack traces from the Scyther engine.
