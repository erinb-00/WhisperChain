import socket
import threading
from user.user import User
import struct
import json
from auth import *

HOST = '0.0.0.0'
PORT = 34567

AI_conn_addr = []

user_list = {}
addrTOuser = {}
connectionList = {}
admin_array = []  # List of admin connections

conn_list = {}

blockedlist = {}  # List of blocked users

# This function handles the initial sign-in or sign-up process for users, admins, and AI connections.
def sign(conn, addr):
    with open("./storage.json", "r") as file:
        userHistory = json.load(file)
    
    conn.send(b"1. Sign In\n2. Sign Up\n")
    data = conn.recv(1024).decode()

    if data.strip() == "I AM AN ADMIN": # Check if the connection is from an admin
        if len(admin_array) > 0:
            conn.send(b"Error: Only one admin connection allowed at a time.\n")
            return -1
        conn.send(b"Admin connection established.\n")
        print(f"Admin connected from {addr}")
        admin_array.append(conn) # Store the admin connection
        admin_array.append(addr) # Store the admin address
        return 0

    if data.split('\n',1)[0].strip() == "I AM AN AI": # Check if the connection is from an AI
        if len(AI_conn_addr) > 0:
            conn.send(b"Error: Only one AI connection allowed at a time.\n")
            return -1
        AI_conn_addr.append(conn) # Store the AI connection
        AI_conn_addr.append(addr) # Store the AI address
        print(data.split('\n', 1)[1].strip())
        AI_conn_addr.append(data.strip()) # Store the AI's public key
        conn.send(b"AI connection established.\n")
        return 1


    while data not in ("1", "2"):
        conn.send(b"Error: Command not Recognized\n")
        data = conn.recv(1024).decode()

    if data == "1": # Sign In
        conn.send(b"Username\nPassword\n")
        signIn(conn,addr, userHistory)
    else: # Sign Up
        conn.send(b"Username\nPassword\nMode\n")
        signUp(conn, addr, userHistory)
    return 2

# This function handles the sign-in process for users.
def signIn(conn, addr, userHistory):

    while True:

        data = conn.recv(1024).decode()
        array = data.split(":") # Split the input data by colon

        if len(array) == 3 and array[0] not in userHistory: # Check if the user is not already registered
            break
        if len(array) != 3: # Check if the input data has the correct number of fields
            conn.send(b"Error: Fill all fields\n")
        if array[0] in userHistory:
            if userHistory[array[0]][0] == array[1]:
                break
        
        conn.send(b"Error: Wrong Username or password\n")

    user_list[array[0]] = User(array[0], array[1], userHistory[array[0]][1], addr, conn, array[2])
    addrTOuser[addr] = array[0]
    print(f"New user: {array}")

# This function handles the sign-up process for new users.
def signUp(conn, addr, userHistory):

    while True:

        data = conn.recv(1024).decode()
        array = data.split(":")

        if len(array) == 4 and array[0] not in userHistory: # Check if the user is not already registered
            break
        if len(array) != 4: # Check if the input data has the correct number of fields
            conn.send(b"Error: Fill all fields\n")
        if array[0] in userHistory or user_list:
            conn.send(b"Error: Username already taken\n") #     If the username is already taken


    userHistory[array[0]] = [array[1], array[2]] # Store the username, password, and mode in the userHistory dictionary
    with open("./storage.json", 'w') as json_file:
        json.dump(userHistory, json_file, indent=4) # Save the userHistory dictionary to a JSON file

    user_list[array[0]] = User(array[0], array[1], array[2], addr, conn, array[3])
    addrTOuser[addr] = array[0]
    print(f"New user: {array}")

# This function displays the list of currently online users to the client.
def displayUsers(conn, addr):

    if len(user_list) < 2: # Check if there are at least two users online 
        conn.send(b"No other users signed up yet.\n")
        return
    if addr in addrTOuser: # Check if the address is in the addrTOuser dictionary
        users_list = [key for key in user_list if key != addrTOuser[addr]] #   Get the list of usernames excluding the current user
    if users_list: # Check if the users_list is not empty
        users_msg = "Currently Online:\n" + "\n".join(users_list) + "\n"
        print(users_msg)
        conn.send(users_msg.encode()) # Send the list of online users to the client
    else:
        conn.send(b"No other users signed up yet.\n")

# This function receives all data from the socket until the specified length is reached.
def recvall(conn, length):
    data = b''
    while len(data) < length:
        more = conn.recv(length - len(data))
        if not more:
            raise EOFError('Socket closed before receiving expected data')
        data += more
    return data

# This function handles sending messages between users, including handling admin commands and AI interactions.
def send_message(conn, addr):
    # figure out who I am
    me = addrTOuser[addr]

    conn.send(AI_conn_addr[2].encode())  # receive AI's public key

    while True:
        try:
            raw = conn.recv(1024)
        except OSError as e:
            print(f"[!] Socket error (peer probably kicked): {e}")
            break

        if not raw:
            # peer closed it via shutdown()
            break
        data = raw.decode().strip()
        print(data)
        if not data:
            break

        if data.strip().startswith("ADMIN"):
            data = me + " is a user that wants to unblock-> " + data.strip().split("ADMIN", 1)[1]
            admin_array[0].send(data.encode())

        if data.strip() == "FLAGtext":
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
                recipient_conn = AI_conn_addr[0]
                recipient_conn.sendall(user_list[me].publicKey.encode())  # send my public key to AI
                recipient_conn.sendall(nonce_len_bytes)
                recipient_conn.sendall(nonce)
                recipient_conn.sendall(ct_len_bytes)
                recipient_conn.sendall(ct)
                recipient_conn.sendall(tag)
                recipient_conn.sendall(me.encode())  # send my username to AI
                continue
            except Exception as e:
                print(f"[!] Error forwarding message to AI: {e}")
                break

        if data.upper() == "REFRESH":
            displayUsers(conn, addr)
            continue

        # ---- first I select whom to talk to ----
        if data.upper() == "NAME":
            # client now sends the target username
            target = conn.recv(1024).decode().strip()

            if target in user_list and target != me: # Check if the target user exists and is not the same as the current user
                if target in blockedlist: # Check if the target user is in the blocked list
                    if me in blockedlist[target]: # Check if the current user is blocked by the target user
                        conn.send(b"You are blocked by this user.\n")
                        continue

                if me in blockedlist: # Check if the current user is in the blocked list
                    if target in blockedlist[me]:
                        conn.send(b"You have blocked this user.\n")
                        continue

                # remember who I'm talking to
                user_list[me].recipient = target

                # exchange public keys
                conn.send(user_list[target].publicKey.encode())          # tell me their key
                user_list[target].conn.send(user_list[me].publicKey.encode())  # tell them my key

                # store mapping so we know later who I meant
                connectionList[user_list[me].recipient] = me
                conn_list[me] = target
                conn_list[target] = me
            else:
                conn.send(b"No such user, or you tried to message yourself\n")
            continue

        # ---- once a NAME has been set, I can start sending encrypted messages ----
        if data.upper() == "MESSAGE" or data.upper() == "END CALL": # Check if the user wants to send a message or end the call
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
            conn.send(b"Unknown command. Use NAME to specify a person to talk to or REFRESH to see who is online\n")

def handle_ai(conn, addr):
    while True:
        data = conn.recv(1024)
        if not data:
            # client disconnected
            break

        cmd = data.decode() #.strip().split('\n', 1)[0]
        print(f"[AI {addr}] → {cmd}")
        if cmd.strip().split('\n', 1)[0].lower() == "true": # Check if the AI wants to block a user for bad behavior
            user = cmd.strip().split('\n', 1)[1]
            recipient = conn_list[user]
            try:
                kick_user(recipient, user)
            except KeyError:
                print(f"[!] Tried to block {user} but no conn list entry.")

def handle_admin(conn, addr):
    while True:
        data = conn.recv(1024)
        if not data:
            # client disconnected
            break

        cmd = data.decode()
        print(f"[ADMIN {addr}] → {cmd}")

        if cmd.upper() == "CURRENT USERS ONLINE": # Display the list of currently online users
            displayUsers(conn, addr) # Display the list of online users
            continue

        elif cmd.upper() == "CURRENT BLOCKED USERS": # Display the list of currently blocked users
            conn.send(str(blockedlist).encode()) # Display the blocked list
            continue

        elif cmd.upper().startswith("UNBLOCK"): # Unblock a user
            parts = cmd.split(" ")
            if len(parts) != 3: # Check if the command has the correct number of parts
                conn.send(b"Usage: UNBLOCK <username> <username>\n") # Check if the command is valid
                continue
            username1 = parts[1] # The user who is unblocking
            username2 = parts[2] # The user who is being unblocked
            if username1 in blockedlist:
                if username2 in blockedlist[username1]: # Check if the user is in the blocked list
                    blockedlist[username1].remove(username2) # Remove the user from the blocked list
            else:
                conn.send(f"{username2} was not blocked\n".encode())
            continue

def kick_user(username, me):
    global user_list, blockedlist # Use the global user_list and blockedlist dictionaries
    if username not in user_list: # Check if the user exists in the user_list
        print(f"[!] User {username} not found.") # Print an error message if the user is not found
        return False
    if me in blockedlist: # Check if the user who is blocking exists in the blockedlist
        blockedlist[me].append(username) # Add the user to the blocked list of the user who is blocking
    else:
        blockedlist[me] = [username] # Create a new blocked list for the user who is blocking


# This function handles the client connection, allowing users to sign in, sign up, and interact with the server.
def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    flag = True
    try:
        with conn:
            flag = sign(conn, addr) # Determine if the connection is from a user, admin, or AI
            if flag == 2: # If the connection is from a user
                displayUsers(conn, addr) # Display the list of currently online users
                send_message(conn, addr) # Handle sending messages between users
            elif flag == 1: # If the connection is from an AI
                handle_ai(conn, addr) # Handle AI interactions
            elif flag == 0: # If the connection is from an admin
                handle_admin(conn, addr) # Handle admin commands
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
        print(f"[!] Connection with {addr} closed unexpectedly: {e}")
    except Exception as e:
        print(f"[!] Unexpected error with {addr}: {e}")
    finally:
        print(f"[-] Disconnected {addr}")
        if addr in addrTOuser:
            if addrTOuser[addr] in user_list:
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