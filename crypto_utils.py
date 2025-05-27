import base64
import json
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

# 1) Derive a *64-byte* key for SIV mode
def create_key() -> bytes:
    password = b"password"                       # your master secret
    salt     = b"placeholder_salt"               # 16-bytes, fixed
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,                               # AES-SIV wants 64 bytes
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password)                  # raw key for AESSIV

# 2) Deterministic encryption
def crypt_cred(plaintext: str, key: bytes) -> str:
    aessiv = AESSIV(key)
    ct = aessiv.encrypt(                             # no AD; you can supply [], or a list
        associated_data=[],
        data=plaintext.encode()
    )
    return base64.urlsafe_b64encode(ct).decode()

# 3) Deterministic decryption
def decrypt_cred(token: str, key: bytes) -> str:
    aessiv = AESSIV(key)
    ct = base64.urlsafe_b64decode(token)
    pt = aessiv.decrypt(                             # must use same AD list
        associated_data=[],
        data=ct
    )
    return pt.decode()

# 4) Example of adding to your JSON store
def add_cred(service, username, password, key):
    with open("./storage.json","r") as f:
        data = json.load(f)
    data[1][service] = {
        "username": username,
        "password": crypt_cred(password, key)
    }
    with open("./storage.json","w") as f:
        json.dump(data, f, indent=4)
