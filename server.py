import socket
import threading
from user.user import User

HOST = '0.0.0.0'
PORT = 23456

user_list = {}

def sign(conn, addr):
    
    conn.send(b"1. Sign In\n2. Sign Up\n")
    data = conn.recv(1024).decode()

    while data not in ("1", "2"):
        conn.send(b"Error: Command not Recognized\n")
        data = conn.recv(1024).decode()

    if data == "1":
        conn.send(b"Username\nPassword\n")
    else:
        conn.send(b"Name\nUsername\nPassword\nMode\n")
        signUp(conn, addr)

def signUp(conn, addr):

    data = conn.recv(1024).decode()
    array = data.split(":")

    while len(array) != 5:
        conn.send(b"Error: Fill all fields\n")
        data = conn.recv(1024).decode()
        array = data.split(":")

    user_list[array[0]] = User(array[0], array[1], array[2], array[3], addr, conn, array[4])
    print(f"New user: {array}")

def displayUsers(conn, addr):

    if not user_list:
        conn.send(b"No users signed up yet.\n")
        return
    users_msg = "\n".join(key for key in user_list) + "\n"
    conn.send(users_msg.encode())

def send_message(conn, addr):
    while True:
        data = conn.recv(1024).decode().strip()
        if not data:
            break

        if data in user_list:
            key = user_list[data].publicKey
            conn.send(key.encode())
            user_list[data].conn.send(conn.recv(1024))
            user_list[data].conn.send(conn.recv(1024))
            user_list[data].conn.send(conn.recv(1024))
            user_list[data].conn.send(conn.recv(1024))
        else:
            conn.send(b"No user with that name is currently on the server\n")
            displayUsers(conn, addr)


def handle_client(conn, addr):

    print(f"[+] Connection from {addr}")
    with conn:
        sign(conn, addr)
        displayUsers(conn, addr)
        send_message(conn, addr)
    print(f"[-] Disconnected {addr}")

def main():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        s.settimeout(1.0)   # ← allow accept() to time out every 1s
        print(f"Server listening on {HOST}:{PORT}")

        try:
            while True:
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    # just loop back and check for Ctrl+C
                    continue
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\nServer shutting down.")

if __name__ == "__main__":
    main()
