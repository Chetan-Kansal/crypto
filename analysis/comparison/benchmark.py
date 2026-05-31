import sys
import os
import time
import base64
import tracemalloc

# Add project root to path so we can import crypto modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from crypto.dh_utils import generate_dh_private_key, get_public_bytes, load_public_key, perform_key_exchange
from crypto.rsa_utils import generate_rsa_keypair, get_rsa_public_bytes, load_rsa_public_key, rsa_encrypt_secret, rsa_decrypt_secret
from crypto.elgamal_utils import generate_elgamal_keypair, elgamal_encrypt, elgamal_decrypt
from crypto.aes_utils import encrypt_message, decrypt_message
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key(shared_secret):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'benchmark')
    return hkdf.derive(shared_secret)

def format_size(bytes_size):
    return f"{bytes_size / 1024:.2f} KB"

def benchmark_ecc(file_path):
    print(f"\n--- Benchmarking ECC (ECDH + AES) on {os.path.basename(file_path)} ---")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 1. Key Generation
    start_time = time.perf_counter()
    alice_priv = generate_dh_private_key()
    bob_priv = generate_dh_private_key()
    alice_pub = get_public_bytes(alice_priv)
    bob_pub = get_public_bytes(bob_priv)
    key_gen_time = time.perf_counter() - start_time
    
    # 2. Key Exchange (Encapsulation equivalent)
    start_time = time.perf_counter()
    shared_secret_alice = perform_key_exchange(alice_priv, load_public_key(bob_pub))
    shared_secret_bob = perform_key_exchange(bob_priv, load_public_key(alice_pub))
    aes_key = derive_key(shared_secret_alice)
    key_exchange_time = time.perf_counter() - start_time
    
    # 3. Encryption (AES)
    start_time = time.perf_counter()
    tracemalloc.start()
    # AES expects string in our current implementation, we need to handle bytes for multimedia
    # We will modify the benchmark to use raw AES logic to support binary data
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, data, None)
    current, peak_enc_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    encryption_time = time.perf_counter() - start_time
    
    # 4. Decryption (AES)
    start_time = time.perf_counter()
    aes_key_bob = derive_key(shared_secret_bob)
    aesgcm_bob = AESGCM(aes_key_bob)
    plaintext = aesgcm_bob.decrypt(iv, ciphertext, None)
    decryption_time = time.perf_counter() - start_time
    
    assert plaintext == data, "Decryption failed!"
    
    key_size = len(alice_pub) + len(bob_pub)
    ciphertext_size = len(iv) + len(ciphertext)
    
    return {
        'Algo': 'ECC',
        'KeyGen(s)': key_gen_time,
        'KeyEx(s)': key_exchange_time,
        'Enc(s)': encryption_time,
        'Dec(s)': decryption_time,
        'KeySize(B)': key_size,
        'CTSize(B)': ciphertext_size,
        'PeakMem(KB)': peak_enc_mem / 1024
    }

def benchmark_rsa(file_path):
    print(f"\n--- Benchmarking RSA (RSA-KEM + AES) on {os.path.basename(file_path)} ---")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 1. Key Generation
    start_time = time.perf_counter()
    bob_priv = generate_rsa_keypair(2048)
    bob_pub_bytes = get_rsa_public_bytes(bob_priv)
    key_gen_time = time.perf_counter() - start_time
    
    # 2. Key Encapsulation (Alice generates AES key, encrypts with Bob's public key)
    start_time = time.perf_counter()
    aes_key_alice = os.urandom(32)
    bob_pub = load_rsa_public_key(bob_pub_bytes)
    encrypted_aes_key = rsa_encrypt_secret(bob_pub, aes_key_alice)
    
    # Bob decrypts the AES key
    aes_key_bob = rsa_decrypt_secret(bob_priv, encrypted_aes_key)
    key_exchange_time = time.perf_counter() - start_time
    
    assert aes_key_alice == aes_key_bob
    
    # 3. Encryption (AES)
    start_time = time.perf_counter()
    tracemalloc.start()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(aes_key_alice)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, data, None)
    current, peak_enc_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    encryption_time = time.perf_counter() - start_time
    
    # 4. Decryption (AES)
    start_time = time.perf_counter()
    aesgcm_bob = AESGCM(aes_key_bob)
    plaintext = aesgcm_bob.decrypt(iv, ciphertext, None)
    decryption_time = time.perf_counter() - start_time
    
    assert plaintext == data, "Decryption failed!"
    
    key_size = len(bob_pub_bytes)
    ciphertext_size = len(iv) + len(ciphertext) + len(encrypted_aes_key)
    
    return {
        'Algo': 'RSA',
        'KeyGen(s)': key_gen_time,
        'KeyEx(s)': key_exchange_time,
        'Enc(s)': encryption_time,
        'Dec(s)': decryption_time,
        'KeySize(B)': key_size,
        'CTSize(B)': ciphertext_size,
        'PeakMem(KB)': peak_enc_mem / 1024
    }

def benchmark_elgamal(file_path):
    print(f"\n--- Benchmarking ElGamal (ElGamal-KEM + AES) on {os.path.basename(file_path)} ---")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 1. Key Generation
    start_time = time.perf_counter()
    bob_keys = generate_elgamal_keypair()
    key_gen_time = time.perf_counter() - start_time
    
    # 2. Key Encapsulation (Alice encrypts AES key with Bob's public key)
    start_time = time.perf_counter()
    aes_key_alice = os.urandom(32)
    c1, c2 = elgamal_encrypt(bob_keys['public_key'], aes_key_alice)
    
    # Bob decrypts AES key
    aes_key_bob = elgamal_decrypt(bob_keys['private_key'], c1, c2)
    key_exchange_time = time.perf_counter() - start_time
    
    assert aes_key_alice == aes_key_bob, f"Key mismatch in ElGamal {aes_key_alice.hex()} != {aes_key_bob.hex()}"
    
    # 3. Encryption (AES)
    start_time = time.perf_counter()
    tracemalloc.start()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(aes_key_alice)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, data, None)
    current, peak_enc_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    encryption_time = time.perf_counter() - start_time
    
    # 4. Decryption (AES)
    start_time = time.perf_counter()
    aesgcm_bob = AESGCM(aes_key_bob)
    plaintext = aesgcm_bob.decrypt(iv, ciphertext, None)
    decryption_time = time.perf_counter() - start_time
    
    assert plaintext == data, "Decryption failed!"
    
    # Estimate key sizes (bytes)
    key_size = 256 # 2048-bit public key y
    ciphertext_size = len(iv) + len(ciphertext) + 512 # 512 bytes for c1 and c2 in ElGamal
    
    return {
        'Algo': 'ElGamal',
        'KeyGen(s)': key_gen_time,
        'KeyEx(s)': key_exchange_time,
        'Enc(s)': encryption_time,
        'Dec(s)': decryption_time,
        'KeySize(B)': key_size,
        'CTSize(B)': ciphertext_size,
        'PeakMem(KB)': peak_enc_mem / 1024
    }

def print_results(results):
    import csv
    print(f"\n{'Algorithm':<10} | {'KeyGen (s)':<12} | {'KeyEx (s)':<12} | {'Enc (s)':<12} | {'Dec (s)':<12} | {'KeySize(B)':<10} | {'PeakMem(KB)':<12}")
    print("-" * 95)
    for res in results:
        print(f"{res['Algo']:<10} | {res['KeyGen(s)']:<12.5f} | {res['KeyEx(s)']:<12.5f} | {res['Enc(s)']:<12.5f} | {res['Dec(s)']:<12.5f} | {res['KeySize(B)']:<10} | {res['PeakMem(KB)']:<12.2f}")
    
    # Save to CSV
    csv_exists = os.path.isfile('benchmark_results.csv')
    with open('benchmark_results.csv', 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        if not csv_exists:
            writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    test_files = [
        'test_data/1_page.txt',
        'test_data/10_page.txt',
        'test_data/50_page.txt',
        'test_data/sample_image.jpg'
    ]
    
    # Change dir to analysis/comparison so paths work
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Clear previous csv
    if os.path.exists('benchmark_results.csv'):
        os.remove('benchmark_results.csv')
    
    for tf in test_files:
        if not os.path.exists(tf):
            print(f"Error: {tf} not found. Run generate_test_data.py first.")
            sys.exit(1)
            
        print(f"\n{'='*50}\nTesting File: {tf} (Size: {format_size(os.path.getsize(tf))})\n{'='*50}")
        
        results = []
        # Run ECC
        res_ecc = benchmark_ecc(tf)
        results.append(res_ecc)
        
        # Run RSA
        res_rsa = benchmark_rsa(tf)
        results.append(res_rsa)
        
        # Run ElGamal
        res_elg = benchmark_elgamal(tf)
        results.append(res_elg)
        
        print_results(results)
