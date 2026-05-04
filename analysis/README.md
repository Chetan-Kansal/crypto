# Cryptanalysis and Attack Framework

This directory contains the full experimental cryptanalysis module for the multi-user chat system.
It evaluates three system versions:
1. `plain_chat`: Insecure baseline.
2. `encrypted_chat`: Ephemeral DH + AES-GCM (Static session key).
3. `forward_secret_chat`: Ephemeral DH + AES-GCM + Active Key Rotation.

## Directory Structure
- `attack_scripts/`: Independent scripts simulating 5 core attacks (Sniffing, DB Leak, Key Compromise, Replay, Tampering).
- `attack_results/`: JSON logs produced by running the attack scripts.
- `comparison/`: Matrix and report generators mapping experimental results into a final paper.
- `packet_capture_logs/`: Directory for saving raw packet captures (PCAP).
- `screenshots/`: Directory for storing visual proofs for the paper.

## How to Run

Execute any attack script against a specific mode:
```bash
python attack_scripts/passive_sniffer.py --mode forward_secret_chat
python attack_scripts/key_compromise_test.py --mode encrypted_chat
```

Generate the final consolidated markdown report:
```bash
python comparison/generate_comparison_report.py
```
This reads all JSON logs and builds `comparison/attack_comparison_report.md`.
