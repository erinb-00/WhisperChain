# ecc_e2ee.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

# 1. Generate or load your EC key pair
def generate_ec_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

# 2. Serialize public key to bytes for exchange
def serialize_public_key(pub):
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pub_bytes):
    return serialization.load_pem_public_key(pub_bytes)

# 3. Derive shared AES key
def derive_aes_key(my_priv, their_pub_bytes):
    their_pub = load_public_key(their_pub_bytes)
    shared_secret = my_priv.exchange(ec.ECDH(), their_pub)
    # HKDF to stretch into 32-byte key
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)

# 4. AES-GCM encrypt/decrypt
def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    nonce = urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ct, encryptor.tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def ecc_pubkey_to_string(pubkey) -> str:
    """
    Serialize an EC public key to a PEM-format string.
    """
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def string_to_ecc_pubkey(pem_str: str):
    """
    Load an EC public key object from a PEM-format string.
    """
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8')
    )

# --- Demo handshake & message exchange ---
if __name__ == "__main__":
    # Alice & Bob generate keypairs
    priv_a, pub_a = generate_ec_keypair()
    priv_b, pub_b = generate_ec_keypair()

    # Exchange public keys
    pub_a_bytes = serialize_public_key(pub_a)
    pub_b_bytes = serialize_public_key(pub_b)

    # Each derives the same AES key
    key_a = derive_aes_key(priv_a, pub_b_bytes)
    key_b = derive_aes_key(priv_b, pub_a_bytes)
    assert key_a == key_b

    # Encrypt and decrypt
    nonce, ct, tag = aes_gcm_encrypt(key_a, b"Secret via ECC!")
    msg = aes_gcm_decrypt(key_b, nonce, ct, tag)
    print(msg)  # b'Secret via ECC!'
