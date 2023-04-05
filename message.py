import requests
import json

# Set the chat server URL
url = 'http://localhost:50660/'

# Log in to the chat server
login_message = {'type': 'login'}
response = requests.post(url, json=login_message)
print(response.text)

# Loop to send multiple messages
while True:
    # Get message text from user input
    message_text = input("Enter message: ")

    # Check if user wants to quit
    if message_text.lower() == 'quit':
        break

    # Send message to the chat server
    message = {'type': 'message', 'text': message_text}
    response = requests.post(url, json=message)
    print(response.text)
