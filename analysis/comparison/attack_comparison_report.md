# Cryptanalysis and Attack Comparison Report

This document summarizes the experimental cryptanalysis of three distinct system architectures:

1. **Version 1 (Insecure Baseline)**: Plaintext chat with no encryption.
2. **Version 2 (Encrypted Chat)**: Ephemeral DH + AES-GCM (Static Session).
3. **Version 3 (Forward-Secret Chat)**: Ephemeral DH + AES-GCM + Active Key Rotation.

## 1. Attack Matrix Overview

| Attack Vector | Plain Chat | Encrypted Chat | Forward-Secret Chat |
|--------------|------------|----------------|---------------------|
| **Passive Eavesdropping** | plaintext visible | ciphertext only | ciphertext only |
| **Database Leak** | full chat history exposed | ciphertext only | ciphertext only |
| **Session Key Compromise** | not applicable | entire session exposed | only current key window exposed |
| **Replay Attack** | accepted | may be accepted | rejected |
| **Message Tampering** | accepted | rejected | rejected |

## 2. Experimental Execution Logs

### Passive Sniffer
#### Mode: `plain_chat`
- **Observed Data**: Hello Top Secret Project
- **Result**: plaintext visible
- **Security Impact**: Critical - Full confidentiality loss

#### Mode: `encrypted_chat`
- **Observed Data**: K2GU6tMWo8kd9fH86GY1yFlvyp9gvh1ApUiR/GPvjEdR9YIoTE3xkXoreYOJuaKoVRcg9g==
- **Result**: ciphertext only
- **Security Impact**: Low - Confidentiality preserved via AES-GCM

#### Mode: `forward_secret_chat`
- **Observed Data**: uuaMuM0auzSWPErNu0/E4ZuihCSIWnjMDa44axn1nqod2P+UvsKNVmIIl3jbarnUYwF0rg== (with periodic rekey events)
- **Result**: ciphertext only
- **Security Impact**: Low - Confidentiality preserved with perfect forward secrecy

### Db Leak
#### Mode: `plain_chat`
- **Observed Data**: ['Hello Top Secret Project', 'Hello Top Secret Project', 'Hello Top Secret Project']
- **Result**: full chat history exposed
- **Security Impact**: Critical - All past data leaked

#### Mode: `encrypted_chat`
- **Observed Data**: ['WFjo1E9u2soa1avqpYfSK1aIjYpHphjxTRVIVDT7gIeE', 'FUJed4TojZ4MJpjEvKd8uTENrd57pzcbBgtuNNC2wpWk', 'pGEku6/UM4+s16GUemKs+eUfNwGYzCwO0xstAWTSFjSl']
- **Result**: ciphertext only
- **Security Impact**: Moderate - Ciphertexts leaked, but secure unless static key compromised

#### Mode: `forward_secret_chat`
- **Observed Data**: ['/wWH8BAT1k9zQY5LasD6T28tm98WTcMYw+scAAF/QnUG', '/FQ8sgJp+Q3S5rTRd+riLlgcumDx0fgMuM/PDfYhTPU5', 'Al47OXaU2L1chawEjhthe5qH+6EC0q1/ZLVeFZnaVp5n']
- **Result**: ciphertext only
- **Security Impact**: Low - Ciphertexts leaked, securely unreadable without ephemeral keys

### Key Compromise
#### Mode: `plain_chat`
- **Observed Data**: Not Applicable - No key exists
- **Result**: not applicable
- **Security Impact**: Critical - Always readable

#### Mode: `encrypted_chat`
- **Observed Data**: Decrypted 3/3 historical messages
- **Result**: entire session exposed
- **Security Impact**: High - Static session key compromises all past history

#### Mode: `forward_secret_chat`
- **Observed Data**: Decrypted 1/3 historical messages
- **Result**: only current key window exposed
- **Security Impact**: Low - Forward secrecy successfully protected older messages

### Replay Attack
#### Mode: `plain_chat`
- **Observed Data**: Replayed plaintext packet successfully
- **Result**: accepted
- **Security Impact**: High - Receiver processes duplicate message

#### Mode: `encrypted_chat`
- **Observed Data**: Ciphertext accepted (AES-GCM checks integrity, but not sequence natively without tracking)
- **Result**: may be accepted
- **Security Impact**: Moderate - Dependent on application-level nonce tracking

#### Mode: `forward_secret_chat`
- **Observed Data**: Replayed packet failed decryption (Old Key invalidated)
- **Result**: rejected
- **Security Impact**: Low - Key rotation inherently prevents long-term replays

### Tamper Attack
#### Mode: `plain_chat`
- **Observed Data**: Modified plaintext accepted
- **Result**: accepted
- **Security Impact**: High - No integrity checks

#### Mode: `encrypted_chat`
- **Observed Data**: AES-GCM Authentication Tag verification failed.
- **Result**: rejected
- **Security Impact**: Low - Integrity strictly preserved by AES-GCM

#### Mode: `forward_secret_chat`
- **Observed Data**: AES-GCM Authentication Tag verification failed.
- **Result**: rejected
- **Security Impact**: Low - Integrity strictly preserved by AES-GCM

## 3. Final Attack Conclusions

- **Plaintext Chat** is completely vulnerable to all passive and active attacks.
- **Encrypted Chat** significantly improves confidentiality and completely solves tampering (via AES-GCM tags). However, it is vulnerable to Session Key Compromise, leaking all historical messages.
- **Forward-Secret Chat** provides the highest tier of security. By rotating the AES-GCM key periodically via HKDF, even if an attacker compromises the server memory, they can only read the current window of messages. All past data remains securely encrypted.
