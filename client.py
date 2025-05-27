import socket
import threading
import sys
from encryption import *
import struct
from crypto_utils import *
from collections import deque

HOST = '127.0.0.1'
PORT = 34567

priv, pub = generate_ec_keypair() # Generate an EC keypair for the client
AI_key = None # This will hold the AES key for AI communication
pem = serialize_public_key(pub) # Serialize the public key to PEM format
shared_key = None # This will hold the shared AES key for communication with other clients
encrypt_key = False # This will hold the encryption key for usernames
q = deque() # This will hold the last 3 messages received from other users

send_key_event = threading.Event()
start_encryption_event = threading.Event()

# Function to receive all bytes from a socket until the specified length is reached
# This is useful for receiving fixed-length encrypted messages
def recvall(sock, length):
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise EOFError('Socket closed before receiving expected data')
        data += more
    return data

# Function to receive messages from the server
def receive_messages(sock):
    global shared_key, priv, AI_key
    while True:
        try:

            # Check if encryption is enabled
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

                plaintext = aes_gcm_decrypt(shared_key, nonce, ct, tag) # Decrypt the message
                if plaintext.decode() == "END CALL": # End of call signal
                    print("\n[Server]> CALL WITH CLIENT...")
                    start_encryption_event.clear() # Reset the encryption event
                    shared_key = None
                    continue
                print(f"\n[Server]> {plaintext.decode()}") 
                if len(q) == 3: # Limit the queue to 3 messages
                    q.popleft()
                q.append(plaintext.decode()) # Store the decrypted message in the queue
                continue

            chunk = sock.recv(1024) # Read up to 1024 bytes. this is the plaintext phase
            if not chunk:
                print("\n[!] Server closed the connection.")
                sys.exit(0)

            # Else we're still in plaintext phase
            try:
                text = chunk.decode()
            except UnicodeDecodeError:
                print(f"\n[!] Received undecodable bytes during plaintext phase.")
                continue

            # Check if the text contains the marker
            marker = "Currently Online:\n" # This is the marker used to identify the user block in the text
            if marker in text: 
                header, user_block = text.split(marker, 1)
                lines = user_block.strip().split('\n')
                global encrypt_key
                decrypted_users = [decrypt_cred(line, encrypt_key) for line in lines] # Decrypt each username in the user block
                text = marker + "\n".join(decrypted_users) + "\n" # Reconstruct the text with decrypted usernames

            elif text.strip().startswith("Username") or text.strip() == "Error: Fill all fields" or text.strip() == "Error: Username already taken" or text.strip() == "Error: Wrong Username or password": # These are error messages that should not be decrypted
                send_key_event.set()

            elif shared_key is None and b"-----BEGIN PUBLIC KEY-----" in chunk: # This is the marker used to identify the public key in the text
                pem_data = chunk
                while b"-----END PUBLIC KEY-----" not in pem_data: # Read until the end of the PEM block
                    more = sock.recv(1024)
                    if not more:
                        raise RuntimeError("Connection closed while reading PEM")
                    pem_data += more
                if pem_data.decode('utf-8').split('\n',1)[0].strip() == "I AM AN AI":
                    AI_key = derive_aes_key(priv, pem_data.decode('utf-8').split('\n',1)[1].strip().encode('utf-8')) # Derive the AES key from the received public key
                    print("\n[*] Shared AES key with AI established.") # This is the AI key establishment message
                    continue
                shared_key = derive_aes_key(priv, pem_data) # Derive the AES key from the received public key
                start_encryption_event.set()
                print("\n[*] Shared AES key with another client established.") # This is the key establishment message for other clients
                q.clear()
                continue

            print(f"\n[Server]>\n{text}", end="") # Print the received message from the server

        except Exception as e:
            print(f"\n[!] Receive error: {e}")
            sys.exit(0)


def main():
    global shared_key
    global encrypt_key
    global AI_key
    encrypt_key = create_key() # Generate a new encryption key
    encrypt = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")

        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

        while True:

            try:
                msg = input("Send> ")

                if msg.strip().startswith("ADMIN"): # This is a command for administrators
                    array = msg.split(" ") 
                    if len(array) != 2: # Check if the command is valid
                        print("[!] Invalid format. Use: ADMIN <username to unblock>")
                        continue
                    msg = "ADMIN" + crypt_cred(array[1], encrypt_key) # encrypt the username with the encryption key so the administrator cannot see it 

                if encrypt:
                    encrypted = crypt_cred(msg, encrypt_key)   # Encrypt your name with the encryption key so the server cannot see it
                    msg = encrypted
                    encrypt = False               

                if msg == "NAME":
                    encrypt = True # This is a command to encrypt the next message

                if start_encryption_event.is_set():
                    if msg == "END CALL": # This is a command to end the call with users
                        s.sendall(msg.encode())
                    elif msg == "FLAGtext": # This is a command to send the flag text to the AI
                        s.sendall(b"FLAGtext")
                        msg = ""
                        while q:
                            msg = msg + str(q.popleft()) + "\n"
                        nonce, ct, tag = aes_gcm_encrypt(AI_key, msg.encode())
                        s.sendall(struct.pack('!H', len(nonce)))  # 2 bytes for nonce length
                        s.sendall(nonce)
                        s.sendall(struct.pack('!I', len(ct)))     # 4 bytes for ciphertext length
                        s.sendall(ct)
                        s.sendall(tag)  # Tag is always 16 bytes so no need to send length
                        print(msg)
                        continue
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

                if send_key_event.is_set(): # This is a command to send your name password and public key to the server
                    global pem
                    if ':' not in msg:
                        print("[!] Invalid format.")
                        continue
                    prefix, rest = msg.split(':', 1) # Split the message into prefix and rest
                    encrypted = crypt_cred(prefix.strip(), encrypt_key) # Encrypt the prefix (username) with the encryption key
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