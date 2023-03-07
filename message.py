import websocket
import json

# Set up the WebSocket connection
print("Connecting to server...")
ws = websocket.create_connection("ws://localhost:8000/")
print("Connected to server.")

# Log in to the chat server
login_message = {'type': 'login'}
ws.send(json.dumps(login_message))

# Send and receive messages to/from the chat server
while True:
    # Wait for user input
    message_text = input("Enter message: ")

    # Send a message to the chat server
    message = {'type': 'message', 'text': message_text}
    ws.send(json.dumps(message))

    # Receive messages from the chat server
    message = ws.recv()
    print(message)
