import os

# RFC 3526 - 2048-bit MODP Group
P_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2

def generate_elgamal_keypair():
    """Generates an ElGamal private/public keypair."""
    # Private key is a random integer x such that 1 < x < p-1
    # We'll use 256 bits (32 bytes) for the private key size for performance,
    # which is standard for a 2048-bit group.
    x_bytes = os.urandom(32)
    x = int.from_bytes(x_bytes, byteorder='big')
    
    # Public key is g^x mod p
    y = pow(G, x, P_2048)
    
    return {'private_key': x, 'public_key': y, 'p': P_2048, 'g': G}

def elgamal_encrypt(public_key, message_bytes):
    """
    Encrypts a small message (e.g., an AES key) using ElGamal.
    Returns (c1, c2) where:
    c1 = g^k mod p
    c2 = (m * y^k) mod p
    """
    p = P_2048
    g = G
    y = public_key
    
    # Convert message to integer
    m = int.from_bytes(message_bytes, byteorder='big')
    if m >= p:
        raise ValueError("Message is too large for the modulus.")
        
    # Generate ephemeral key k
    k_bytes = os.urandom(32)
    k = int.from_bytes(k_bytes, byteorder='big')
    
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    
    return (c1, c2)

def elgamal_decrypt(private_key, c1, c2):
    """
    Decrypts an ElGamal encrypted message.
    m = (c2 * c1^(p-1-x)) mod p
    """
    p = P_2048
    x = private_key
    
    # Calculate s = c1^x mod p
    s = pow(c1, x, p)
    
    # Calculate modular inverse of s
    # s_inv = s^(p-2) mod p (Fermat's Little Theorem)
    s_inv = pow(s, p - 2, p)
    
    m = (c2 * s_inv) % p
    
    # Assuming message was originally 32 bytes (like an AES key)
    # We return the raw integer, the caller can convert it back to bytes
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').rjust(32, b'\x00')
