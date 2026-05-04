import os
import json

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../attack_results'))
OUTPUT_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), 'attack_comparison_report.md'))
MATRIX_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), 'attack_matrix.json'))

MODES = ['plain_chat', 'encrypted_chat', 'forward_secret_chat']
ATTACKS = ['passive_sniffer', 'db_leak', 'key_compromise', 'replay_attack', 'tamper_attack']

def generate_report():
    print("[*] Gathering attack results...")
    
    with open(MATRIX_FILE, 'r') as f:
        matrix = json.load(f)
        
    report = []
    report.append("# Cryptanalysis and Attack Comparison Report\n")
    report.append("This document summarizes the experimental cryptanalysis of three distinct system architectures:\n")
    report.append("1. **Version 1 (Insecure Baseline)**: Plaintext chat with no encryption.")
    report.append("2. **Version 2 (Encrypted Chat)**: Ephemeral DH + AES-GCM (Static Session).")
    report.append("3. **Version 3 (Forward-Secret Chat)**: Ephemeral DH + AES-GCM + Active Key Rotation.\n")
    
    report.append("## 1. Attack Matrix Overview\n")
    report.append("| Attack Vector | Plain Chat | Encrypted Chat | Forward-Secret Chat |")
    report.append("|--------------|------------|----------------|---------------------|")
    
    for attack, modes in matrix.items():
        report.append(f"| **{attack}** | {modes['plain_chat']} | {modes['encrypted_chat']} | {modes['forward_secret_chat']} |")
        
    report.append("\n## 2. Experimental Execution Logs\n")
    
    for attack in ATTACKS:
        report.append(f"### {attack.replace('_', ' ').title()}")
        for mode in MODES:
            log_file = os.path.join(RESULTS_DIR, mode, f"{attack}.json")
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    data = json.load(f)
                    report.append(f"#### Mode: `{mode}`")
                    report.append(f"- **Observed Data**: {data['observed_data']}")
                    report.append(f"- **Result**: {data['result']}")
                    report.append(f"- **Security Impact**: {data['security_impact']}\n")
            else:
                report.append(f"#### Mode: `{mode}`")
                report.append("- *No experimental data available.*\n")
                
    report.append("## 3. Final Attack Conclusions\n")
    report.append("- **Plaintext Chat** is completely vulnerable to all passive and active attacks.")
    report.append("- **Encrypted Chat** significantly improves confidentiality and completely solves tampering (via AES-GCM tags). However, it is vulnerable to Session Key Compromise, leaking all historical messages.")
    report.append("- **Forward-Secret Chat** provides the highest tier of security. By rotating the AES-GCM key periodically via HKDF, even if an attacker compromises the server memory, they can only read the current window of messages. All past data remains securely encrypted.\n")

    with open(OUTPUT_FILE, 'w') as f:
        f.write('\n'.join(report))
        
    print(f"[*] Generated publication-ready report at: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_report()
