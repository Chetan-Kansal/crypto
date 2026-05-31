from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_keypair(key_size=2048):
    """Generates an RSA private key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key

def get_rsa_public_bytes(private_key):
    """Serializes the public key to PEM format."""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_rsa_public_key(public_bytes):
    """Loads a PEM serialized public key."""
    return serialization.load_pem_public_key(public_bytes)

def rsa_encrypt_secret(public_key, secret):
    """Encrypts a small secret (like an AES key) using RSA."""
    ciphertext = public_key.encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt_secret(private_key, ciphertext):
    """Decrypts a small secret using RSA."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
