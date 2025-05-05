import socket
import threading
import sys
from encryption import *

HOST = '127.0.0.1'
PORT = 23456

# keypair
priv, pub = generate_ec_keypair()
pem = serialize_public_key(pub)
shared_key = None

# use an Event for cross-thread signaling
send_key_event = threading.Event()
get_pub = threading.Event()

def receive_messages(sock):
    
    global shared_key

    while True:
        try:
            # 1) grab the next chunk of raw bytes
            chunk = sock.recv(1024)
            if not chunk:
                print("\n[!] Server closed the connection.")
                sys.exit(0)

            # 2) check for end-of-signup prompt in text form
            try:
                text = chunk.decode()
                print(f"\n[Server]> {text}", end="")
                if text.strip().endswith("Mode") or text.strip() == "Error: Fill all fields":
                    send_key_event.set()
                # elif text.strip().endswith(":Key"):
                #     global reciever_pub
                #     reciever_pub = text.strip()[:-4]
                #     get_pub.set()
            except UnicodeDecodeError:
                # not plain-text, fall through to binary checks
                pass

            # 3) collect a peer’s public-key PEM and derive our shared AES key
            if shared_key is None and b"-----BEGIN PUBLIC KEY-----" in chunk:
                pem_data = chunk
                while b"-----END PUBLIC KEY-----" not in pem_data:
                    more = sock.recv(1024)
                    if not more:
                        raise RuntimeError("Connection closed while reading PEM")
                    pem_data += more
                shared_key = derive_aes_key(priv, pem_data)
                print("\n[*] Shared AES key established.")
                continue

            # 4) once we have a shared key, decrypt the next message
            if shared_key:
                # we assume the peer sends: [12-byte nonce][ciphertext+tag]
                nonce      = chunk[:12]
                ct_and_tag = sock.recv(1024)
                ct, tag    = ct_and_tag[:-16], ct_and_tag[-16:]
                plaintext  = aes_gcm_decrypt(shared_key, nonce, ct, tag)
                print(f"\n[Server]> {plaintext.decode()}")
                continue

        except Exception as e:
            print(f"\n[!] Receive error: {e}")
            sys.exit(0)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")

        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

        while True:
            nonce = ct = tag = None
            try:
                msg = input("Send> ")

                # if the server just asked for your public key, send it *by itself*
                if send_key_event.is_set():
                    global pem
                    msg = msg + ":" + pem.decode('utf-8')
                    send_key_event.clear()

                elif get_pub.is_set():
                    global priv
                    global reciever_pub
                    key_a = derive_aes_key(priv, reciever_pub.encode('utf-8'))
                    nonce, ct, tag = aes_gcm_encrypt(key_a, msg.encode())
                    get_pub.clear()

            except (EOFError, KeyboardInterrupt):
                msg = 'quit'

            if not msg or msg.lower() == 'quit':
                print("[*] Closing connection.")
                try: s.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                break

            try:
                if nonce is not None:
                    s.sendall(pem)
                    s.sendall(nonce)
                    s.sendall(ct)
                    s.sendall(tag)
                    nonce = ct = tag = None
                else:
                    s.sendall(msg.encode())
            except Exception as e:
                print(f"[!] Send error: {e}")
                break

if __name__ == "__main__":
    main()
