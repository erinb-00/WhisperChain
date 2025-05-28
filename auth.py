import json
import os
import hashlib
import base64

# Check if this is the first time (i.e., file does not exist)
def check_first_time(file_path):
    return not os.path.exists(file_path)

# Hash a password with a given salt using PBKDF2-HMAC-SHA256
def hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)

# Register a new password by generating a new salt and hashing the password
def register(password):
    salt = os.urandom(16)  # Generate a random 16-byte salt
    hashed = hash(password, salt)  # Hash the password with the salt
    return salt, hashed

# Verify username and password against stored credentials
def get_in(username, password):
    with open("./storage.json", "r") as file:
        data = json.load(file)[0]  # Load the first user record
    # Check if the stored password and salt match the provided password and username
    if base64.b64decode(data["password"]) != hash(password, base64.b64decode(data["salt"])) or data["username"] != username:
        return False
    return True

# Change the password and username in the storage file
def change_pass(username, password):
    with open("./storage.json", "r") as file:
        data = json.load(file)  # Load the existing data
        salt, encrypted = register(password)  # Generate new salt and hashed password
        string_salt = base64.b64encode(salt).decode('utf-8')  # Encode salt to store as string
        string_encrypted = base64.b64encode(encrypted).decode('utf-8')  # Encode hashed password
        data[0]["username"] = username  # Update username
        data[0]["password"] = string_encrypted  # Update password
        data[0]["salt"] = string_salt  # Update salt
    with open("./storage.json", "w") as file:
        json.dump(data, file, indent=4)  # Write updated data back to the file
