import socket
import threading
import sys
from encryption import *
import struct
from crypto_utils import *

HOST = '127.0.0.1'
PORT = 34567

priv, pub = generate_ec_keypair()
pem = serialize_public_key(pub)
shared_key = None

send_key_event = threading.Event()
start_encryption_event = threading.Event()

def recvall(sock, length):
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise EOFError('Socket closed before receiving expected data')
        data += more
    return data

def receive_messages(sock):
    global shared_key, priv
    while True:
        try:

            if shared_key:
                if not start_encryption_event.is_set():
                    start_encryption_event.set()
                # Step 1: Receive nonce length and nonce
                nonce_len_bytes = recvall(sock, 2)
                nonce_len = struct.unpack('!H', nonce_len_bytes)[0]
                nonce = recvall(sock, nonce_len)

                # Step 2: Receive ciphertext length and ciphertext
                ct_len_bytes = recvall(sock, 4)
                ct_len = struct.unpack('!I', ct_len_bytes)[0]
                ct = recvall(sock, ct_len)

                # Step 3: Receive tag (16 bytes)
                tag = recvall(sock, 16)

                plaintext = aes_gcm_decrypt(shared_key, nonce, ct, tag)
                if plaintext.decode() == "END CALL":
                    start_encryption_event.clear()
                    shared_key = None
                    continue
                print(f"\n[Server]> {plaintext.decode()}")
                continue

            chunk = sock.recv(1024)
            if not chunk:
                print("\n[!] Server closed the connection.")
                sys.exit(0)

            # Else we're still in plaintext phase
            try:
                text = chunk.decode()
            except UnicodeDecodeError:
                print(f"\n[!] Received undecodable bytes during plaintext phase.")
                continue

            if text.strip().startswith("Username") or text.strip() == "Error: Fill all fields" or text.strip() == "Error: Username already taken" or text.strip() == "Error: Wrong Username or password":
                send_key_event.set()

            elif shared_key is None and b"-----BEGIN PUBLIC KEY-----" in chunk:
                pem_data = chunk
                while b"-----END PUBLIC KEY-----" not in pem_data:
                    more = sock.recv(1024)
                    if not more:
                        raise RuntimeError("Connection closed while reading PEM")
                    pem_data += more
                shared_key = derive_aes_key(priv, pem_data)
                start_encryption_event.set()
                print("\n[*] Shared AES key established.")
                continue

            print(f"\n[Server]>\n{text}", end="")

        except Exception as e:
            print(f"\n[!] Receive error: {e}")
            sys.exit(0)


def main():
    global shared_key
    encrypt_key = create_key()
    encrypt = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")

        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

        while True:

            try:
                msg = input("Send> ")

                if encrypt:
                    encrypted = crypt_cred(msg, encrypt_key)   
                    print(f"Encrypted: {encrypted}") 
                    msg = encrypted
                    encrypt = False               

                if msg == "NAME":
                    encrypt = True

                if start_encryption_event.is_set():
                    if msg == "END CALL":
                        s.sendall(b"END CALL")
                    else:
                        s.sendall(b"MESSAGE")
                    # Encrypt and decrypt
                    nonce, ct, tag = aes_gcm_encrypt(shared_key, msg.encode())
                    s.sendall(struct.pack('!H', len(nonce)))  # 2 bytes for nonce length
                    s.sendall(nonce)
                    s.sendall(struct.pack('!I', len(ct)))     # 4 bytes for ciphertext length
                    s.sendall(ct)
                    s.sendall(tag)  # Tag is always 16 bytes so no need to send length
                    continue

                if send_key_event.is_set():
                    global pem
                    prefix, rest = msg.split(':', 1)
                    encrypted = crypt_cred(prefix.strip(), encrypt_key)
                    msg = f"{encrypted}:{rest}"
                    msg = msg + ":" + pem.decode('utf-8')
                    send_key_event.clear()

            except (EOFError, KeyboardInterrupt):
                msg = 'quit'

            if not msg or msg.lower() == 'quit':
                print("[*] Closing connection.")
                try: s.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                break

            s.sendall(msg.encode())

if __name__ == "__main__":
    main()