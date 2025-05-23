import socket
import threading
from user.user import User
import struct
import json
from auth import *

HOST = '0.0.0.0'
PORT = 34567

user_list = {}
addrTOuser = {}
connectionList = {}

def sign(conn, addr):
    with open("./storage.json", "r") as file:
        userHistory = json.load(file)
    
    conn.send(b"1. Sign In\n2. Sign Up\n")
    data = conn.recv(1024).decode()

    while data not in ("1", "2"):
        conn.send(b"Error: Command not Recognized\n")
        data = conn.recv(1024).decode()

    if data == "1":
        conn.send(b"Username\nPassword\n")
        signIn(conn,addr, userHistory)
    else:
        conn.send(b"Username\nPassword\nMode\n")
        signUp(conn, addr, userHistory)

def signIn(conn, addr, userHistory):

    while True:

        data = conn.recv(1024).decode()
        array = data.split(":")

        if len(array) == 4 and array[0] not in userHistory:
            break
        if len(array) != 4:
            conn.send(b"Error: Fill all fields\n")
        if array[0] in userHistory:
            if userHistory[array[0]][0] == array[1]:
                break
        
        conn.send(b"Error: Wrong Username or password\n")

    user_list[array[0]] = User(array[0], array[1], userHistory[array[0]][1], addr, conn, array[2])
    addrTOuser[addr] = array[0]
    print(f"New user: {array}")

def signUp(conn, addr, userHistory):

    while True:

        data = conn.recv(1024).decode()
        array = data.split(":")

        if len(array) == 4 and array[0] not in userHistory:
            break
        if len(array) != 4:
            conn.send(b"Error: Fill all fields\n")
        if array[0] in userHistory:
            conn.send(b"Error: Username already taken\n")


    userHistory[array[0]] = [array[1], array[2]]
    with open("./storage.json", 'w') as json_file:
        json.dump(userHistory, json_file, indent=4)

    user_list[array[0]] = User(array[0], array[1], array[2], addr, conn, array[3])
    addrTOuser[addr] = array[0]
    print(f"New user: {array}")

def displayUsers(conn, addr):

    if len(user_list) < 2:
        conn.send(b"No other users signed up yet.\n")
        return

    users_list = [key for key in user_list if key != addrTOuser[addr]]
    if users_list:
        users_msg = "\n".join(users_list) + "\n"
        conn.send(users_msg.encode())
    else:
        conn.send(b"No other users signed up yet.\n")

def recvall(conn, length):
    data = b''
    while len(data) < length:
        more = conn.recv(length - len(data))
        if not more:
            raise EOFError('Socket closed before receiving expected data')
        data += more
    return data

def send_message(conn, addr):
    # figure out who I am
    me = addrTOuser[addr]

    while True:
        data = conn.recv(1024).decode().strip()
        print(data)
        if not data:
            break

        # ---- first I select whom to talk to ----
        if data.upper() == "RESET PASSWORD":
            # client now sends the target username
            target = conn.recv(1024).decode().strip()
            userHistory[addrTOuser[addr]][1] = target
            continue

        # ---- first I select whom to talk to ----
        if data.upper() == "NAME":
            # client now sends the target username
            target = conn.recv(1024).decode().strip()

            if target in user_list and target != me:
                # remember who I'm talking to
                user_list[me].recipient = target

                # exchange public keys
                conn.send(user_list[target].publicKey.encode())          # tell me their key
                user_list[target].conn.send(user_list[me].publicKey.encode())  # tell them my key

                # store mapping so we know later who I meant
                connectionList[user_list[me].recipient] = me
            else:
                conn.send(b"No such user, or you tried to message yourself\n")
            continue

        # ---- once a NAME has been set, I can start sending encrypted messages ----
        if data.upper() == "MESSAGE" or data.upper() == "END CALL":
            if user_list[me].recipient is None:
                user_list[me].recipient = connectionList[addrTOuser[addr]]

            try:
                # read the nonce
                nonce_len_bytes = recvall(conn, 2)
                nonce_len = struct.unpack('!H', nonce_len_bytes)[0]
                nonce = recvall(conn, nonce_len)

                # read the ciphertext
                ct_len_bytes = recvall(conn, 4)
                ct_len = struct.unpack('!I', ct_len_bytes)[0]
                ct = recvall(conn, ct_len)

                # read the tag
                tag = recvall(conn, 16)

                # forward it
                recipient_conn = user_list[user_list[me].recipient].conn
                recipient_conn.sendall(nonce_len_bytes)
                recipient_conn.sendall(nonce)
                recipient_conn.sendall(ct_len_bytes)
                recipient_conn.sendall(ct)
                recipient_conn.sendall(tag)

                if data.upper() == "END CALL":
                    conn.sendall(nonce_len_bytes)
                    conn.sendall(nonce)
                    conn.sendall(ct_len_bytes)
                    conn.sendall(ct)
                    conn.sendall(tag)
                    if me in connectionList:
                        del connectionList[me]
                    if user_list[me].recipient in connectionList:
                        del connectionList[user_list[me].recipient]
                    user_list[user_list[me].recipient].recipient = None
                    user_list[me].recipient = None

            except Exception as e:
                print(f"[!] Error forwarding message: {e}")
                break

        else:
            # if you're in plaintext-mode, you could handle other commands here
            conn.send(b"Unknown command. Use NAME or MESSAGE.\n")


def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
        with conn:
            sign(conn, addr)
            displayUsers(conn, addr)
            send_message(conn, addr)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
        print(f"[!] Connection with {addr} closed unexpectedly: {e}")
    except Exception as e:
        print(f"[!] Unexpected error with {addr}: {e}")
    finally:
        print(f"[-] Disconnected {addr}")
        del user_list[addrTOuser[addr]]
        del addrTOuser[addr]


def main():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        s.settimeout(1.0)
        print(f"Server listening on {HOST}:{PORT}")

        try:
            while True:
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\nServer shutting down.")

if __name__ == "__main__":
    main()