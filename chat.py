import getpass
import hashlib
import base64
import threading
import socketserver

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from passlib.hash import pbkdf2_sha256



# Dictionary to store the active sessions
sessions = {}

# Dictionary to store the user accounts
accounts = {}

# Function to create a new user account
def create_account():
    print("Enter a new username:")
    username = input()
    if username in accounts:
        print("Error: That username is already taken.")
        return
    print("Enter a password:")
    password = getpass.getpass()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    # Generate a new RSA key pair for the user
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    # Add the new user to the accounts dictionary
    accounts[username] = {
        "password_hash": password_hash,
        "public_key": public_key,
        "private_key": private_key
    }
    # Clear the password variable
    password = None
    print("Account created successfully.")

# Function to authenticate a user
def authenticate(socket):
    print("Enter your username:")
    username = input()
    if username not in accounts:
        print("Error: Invalid username.")
        return False
    print("Enter your password:")
    password = getpass.getpass()
    # Verify the password hash using passlib
    if not pbkdf2_sha256.verify(password, accounts[username]["password_hash"]):
        print("Error: Incorrect password.")
        return False
    print("Authentication successful.")
    # Generate a new session key for the user
    session_key = get_random_bytes(16)
    # Encrypt the session key with the client's public key
    client_key = RSA.import_key(accounts[username]["public_key"])
    cipher = PKCS1_OAEP.new(client_key)
    ciphertext = cipher.encrypt(session_key)
    # Send the encrypted session key to the client
    socket.send(ciphertext)
    return session_key
    
# Function to encrypt a message with AES
def encrypt_message(message, key):
    try:
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        # Encode the ciphertext and tag in base64
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        tag_b64 = base64.b64encode(tag).decode()
        return (ciphertext_b64, tag_b64)
    except Exception as e:
        print(f"Error: {e}")
        return None

# Function to decrypt a message with AES
def decrypt_message(ciphertext_b64, tag_b64, key):
    try:
        # Decode the ciphertext and tag from base64
        ciphertext = base64.b64decode(ciphertext_b64.encode())
        tag = base64.b64decode(tag_b64.encode())
        cipher = AES.new(key, AES.MODE_EAX, tag)
        message = cipher.decrypt(ciphertext).decode()
        return message
    except Exception as e:
        print(f"Error: {e}")
        return None

# Function to handle incoming messages
def handle_message(session_id, message):
    # Decrypt the message with the session key
    session = sessions[session_id]
    key = session["key"]
    message = decrypt_message(message, key)
    # Print the decrypted message
    print(f"{session['username']}: {message}")

# Function to send a message to a user
def send_message(session_id, recipient, message):
    # Encrypt the message with the session key
    session = sessions[session_id]
    key = session["key"]
    message = encrypt_message(message, key)
    # Send the encrypted message to the recipient
    recipient_session = sessions[recipient]
    recipient_session["socket"].send(message)

# ThreadedTCPRequestHandler class to handle incoming connections
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Authenticate the user
        if not authenticate():
            return
        username = self.client_address[0]
        # Generate a new RSA key pair for the session
        session_key = get_random_bytes(16)
        session_key_rsa = RSA.generate(2048)
        session_public_key = session_key_rsa.publickey()
        session_private_key = session_key_rsa.export_key()

        # Encrypt the session key with the user's public key
        encrypted_session_key = session_public_key.encrypt(session_key, 32)[0]

        # Send the encrypted session key to the user
        self.request.send(encrypted_session_key)

        # Receive the user's response
        response = self.request.recv(1024)

        # Decrypt the user's response with the session private key
        decrypted_response = session_private_key.decrypt(response)

        # Compare the decrypted response to the original session key
        if decrypted_response == session_key:
            # If the response matches the original session key, proceed with the session
            session = {
                "username": username,
                "key": session_key,
                "socket": self.request
            }
            session_id = id(session)
            sessions[session_id] = session
            print(f"{username} has joined the chat.")
        else:
            # If the response does not match the original session key, end the session
            print("Error: Invalid session key.")
            return

# ThreadedTCPServer class to listen for incoming connections
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

# Main function
def main():
    # Create a new user account
    create_account()
    # Start the server
    server = ThreadedTCPServer(("localhost", 1234), ThreadedTCPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print("Server started.")
    # Enter the main loop
    while True:
        # Wait for a command from the user
        command = input()
        # Split the command into parts
        parts = command.split(" ")
        # Process the command
        if parts[0] == "send":
            # Send a message to a user
            session_id = int(parts[1])
            recipient = int(parts[2])
            message = " ".join(parts[3:])
            send_message(session_id, recipient, message)
        elif parts[0] == "exit":
            # Shut down the server
            server.shutdown()
            break

# Run the main function
if __name__ == "__main__":
    main()
