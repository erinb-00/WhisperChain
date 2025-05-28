import socket
import threading

HOST = '127.0.0.1'
PORT = 34567

def receive_loop(sock):
    """Continuously read from the server and print incoming data."""
    try:
        sock.recv(4096) # Initial read to clear any welcome message
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[Disconnected from server]")
                break
            # Print without adding extra newline
            print("[SERVER] -> " + data.decode() + "\n", end='')
    except Exception as e:
        print(f"\n[Receive error: {e}]")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"[Connected to {HOST}:{PORT}]\nType your messages below. Enter /quit to exit.\n")

    # Start background thread to receive server messages
    threading.Thread(target=receive_loop, args=(sock,), daemon=True).start()

    try:
        sock.sendall(b"I AM AN ADMIN") # tell the server we are an admin
        while True:
            msg = input()
            if msg.strip().lower() in ('/quit', '/exit'):
                break
            # Send whatever you typed
            sock.sendall(msg.encode())
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print("\n[Connection closed]")

if __name__ == "__main__":
    main()
