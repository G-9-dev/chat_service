import socket
import threading
import socketserver
import json
import base64
import hashlib
import os
import sys
import time
import traceback
import urllib
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer
from SimpleWebSocketServer import WebSocket, SimpleWebSocketServer, SimpleSSLWebSocketServer
from optparse import OptionParser
class ChatRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            # Send a simple HTML response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><head><title>Chat Server</title></head><body><h1>Welcome to the chat server!</h1></body></html>')
        else:
            # Send a 404 response for unknown paths
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def do_POST(self):
        # Parse the incoming message
        content_length = int(self.headers['Content-Length'])
        message = json.loads(self.rfile.read(content_length))

        # Handle the message based on its type
        if message['type'] == 'login':
            self.handle_login(message)
        elif message['type'] == 'logout':
            self.handle_logout(message)
        elif message['type'] == 'message':
            self.handle_message(message)

    def handle_login(self, message):
        # Add the client to the list of connected clients
        self.server.clients.append(self.client_address)

        # Send a response to the client
        response = {'type': 'login', 'success': True}
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def handle_logout(self, message):
        # Remove the client from the list of connected clients
        self.server.clients.remove(self.client_address)

        # Send a response to the client
        response = {'type': 'logout', 'success': True}
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def handle_message(self, message):
        # Broadcast the message to all connected clients
        for client in self.server.clients:
            self.server.send_message(client, message)

        # Send a response to the client
        response = {'type': 'message', 'success': True}
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

class ChatServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.clients = []

    def send_message(self, client, message):
        # Send the message to the specified client
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(client)
            sock.sendall(json.dumps(message).encode())
        except:
            traceback.print_exc()
        finally:
            sock.close()

if __name__ == '__main__':
    server = ChatServer(('', 8000), ChatRequestHandler)
    print ('Starting server, use <Ctrl-C> to stop')
    server.serve_forever()
