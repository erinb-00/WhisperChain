import google.generativeai as genai
from encryption import *
from google.generativeai.types import GenerationConfig
import socket, sys
import struct

priv, pub = generate_ec_keypair() # Generate an EC keypair for the client
pem = serialize_public_key(pub) # Serialize the public key to PEM format

HOST, PORT = '127.0.0.1', 34567
genai.configure(api_key="") # API key for Gemini AI

def gemini_agent(message):
    model = genai.GenerativeModel("models/gemini-1.5-flash") # Load the Gemini AI model
    resp = model.generate_content(
        contents=f"Respond 'true' if the following message is using abusive language, 'false' if not. Message: {message}",
        generation_config=GenerationConfig(temperature=0.5, max_output_tokens=10)
    ) # Generate a response from the AI
    return resp.text.strip() # Process the AI response

# Function to get encrypted messages from the server
def recvall(sock, length):
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise EOFError('Socket closed before receiving expected data')
        data += more
    return data

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    global pem

    try:
        sock.recv(4096)
        # tell the server we're the AI
        info = "I AM AN AI\n" + pem.decode()
        sock.sendall(info.encode())
        client_public_key = b"" # hold the client's public key
        while True:

            while b"-----END PUBLIC KEY-----" not in client_public_key:
                more = sock.recv(1024)
                print(more.decode(), end="")
                client_public_key += more

            shared_key = derive_aes_key(priv, client_public_key)

            if shared_key:
                nonce_len_bytes = recvall(sock, 2)
                nonce_len = struct.unpack('!H', nonce_len_bytes)[0]
                nonce = recvall(sock, nonce_len)

                # Step 2: Receive ciphertext length and ciphertext
                ct_len_bytes = recvall(sock, 4)
                ct_len = struct.unpack('!I', ct_len_bytes)[0]
                ct = recvall(sock, ct_len)

                # Step 3: Receive tag (16 bytes)
                tag = recvall(sock, 16)
                name = sock.recv(1024).decode().strip()
                plaintext = aes_gcm_decrypt(shared_key, nonce, ct, tag)
                print(f"\n[Client]> {plaintext.decode()}")
            client_public_key = b"" # Reset the public key for the next message

            answer = gemini_agent(plaintext) # Get AI's response
            print("[AI Response] →", answer) # Process the AI response
            answer = answer + "\n" + name # Append the client's name to the response
            sock.sendall(answer.encode()) # Send the AI's response back to the server
    except Exception as e:
        print("Error:", e)
    finally:
        sock.close()

if __name__ == "__main__":
    main()
