from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_dh_private_key():
    """Generates an ephemeral elliptic curve private key (SECP256R1)."""
    return ec.generate_private_key(ec.SECP256R1())

def get_public_bytes(private_key):
    """Serializes the public key to PEM format."""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(public_bytes):
    """Loads a PEM serialized public key."""
    return serialization.load_pem_public_key(public_bytes)

def perform_key_exchange(private_key, peer_public_key):
    """Performs ECDH key exchange to get the shared secret."""
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key
