import requests
import json

# Set the chat server URL
url = 'http://localhost:57988/'

# Log in to the chat server
login_message = {'type': 'login'}
response = requests.post(url, json=login_message)
print(response.text)

# Send a message to the chat server
message_text = input("Enter message: ")
message = {'type': 'message', 'text': message_text}
response = requests.post(url, json=message)
print(response.text)
