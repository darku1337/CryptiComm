import socket
import threading
import sys
import ssl
import datetime
import time
import secrets

# Constants for message, nickname, and connection limits
MAX_MESSAGE_LENGTH = 1024
MAX_NICKNAME_LENGTH = 32
MAX_CONNECTIONS_PER_IP = 5
RATE_LIMIT = 5
CONNECTION_TIMEOUT = 3600 # 1 hr till user timeout

class ChatServer:
    def __init__(self, port):
        """Initialize the chat server with the specified port and set up necessary structures."""
        self.host = 'localhost'  # Server will listen on localhost
        self.port = port  # Port for incoming connections
        self.rooms = {}  # Dictionary to store active rooms and users
        self.clients = {}  # Dictionary to store connected clients and their sockets
        self.client_message_timestamps = {}  # Track message timestamps for rate-limiting
        self.client_ips = {}  # Track connections per IP address
        self.room_admins = {}  # Store room admins
        self.room_owners = {}  # Store room owners
        self.owner_tokens = {}  # Store secure tokens for room ownership recovery

    def generate_owner_token(self):
        """Generate a secure random token for room ownership recovery."""
        return secrets.token_hex(16)

    def start(self):
        """Start the chat server, accept client connections, and manage SSL encryption."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address to avoid binding errors

        # Attempt to bind the server to the specified host and port
        try:
            server_socket.bind((self.host, self.port))
        except socket.error as e:
            print(f"Failed to bind on port {self.port}: {e}")
            sys.exit(1)

        server_socket.listen(5)  # Start listening for up to 5 connections
        print(f"Server started on port {self.port}")

        # Start a thread for the server owner to issue commands
        owner_thread = threading.Thread(target=self.server_owner_commands)
        owner_thread.start()

        # Main server loop to accept clients
        while True:
            try:
                client_socket, client_address = server_socket.accept()  # Accept a new client connection
                ip = client_address[0]
                print(f"New connection from {ip}:{client_address[1]}")

                # Enforce connection limit per IP address
                if self.client_ips.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
                    print(f"Rejected connection from {ip}: too many connections.")
                    client_socket.close()
                    continue

                self.client_ips[ip] = self.client_ips.get(ip, 0) + 1

                # Set up SSL/TLS encryption for the client connection
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.load_cert_chain(certfile='server.crt', keyfile='server.key')
                client_socket = context.wrap_socket(client_socket, server_side=True)

                # Start a new thread to handle the connected client
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                client_thread.start()
            except (KeyboardInterrupt, SystemExit):
                print("Server shutting down...")
                break

        server_socket.close()

    def server_owner_commands(self):
        """Allows server owner to issue commands like banning or kicking users."""
        while True:
            command = input("Server Owner Command: ").strip()

            if command == "list users":
                print("Connected users: ", list(self.clients.keys()))
            elif command.startswith("ban"):
                parts = command.split(' ', 1)
                if len(parts) > 1:
                    nickname = parts[1]
                    self.ban_user(nickname)
            elif command.startswith("kick"):
                parts = command.split(' ', 1)
                if len(parts) > 1:
                    nickname = parts[1]
                    self.kick_user(nickname)
            elif command.startswith("announce"):
                parts = command.split(' ', 1)
                if len(parts) > 1:
                    self.announce_message(parts[1])

    def handle_client(self, client_socket, client_address):
        """Handle client connection, nickname registration, and message processing."""
        ip = client_address[0]

        # Ask the client for a nickname
        while True:
            client_socket.sendall(f"Enter your nickname (max {MAX_NICKNAME_LENGTH} characters): ".encode('utf-8'))
            nickname = client_socket.recv(1024).decode('utf-8').strip()

            # Ensure nickname is within valid length
            if len(nickname) > MAX_NICKNAME_LENGTH:
                client_socket.sendall(f"Nickname too long. Maximum length is {MAX_NICKNAME_LENGTH} characters. Please pick a shorter nickname.\n".encode('utf-8'))
                continue

            # Check if the nickname already exists (e.g., reconnecting users)
            if nickname in self.clients:
                client_socket.sendall(f"Nickname '{nickname}' is already taken. Please choose a different nickname.\n".encode('utf-8'))
                continue

            break

        # Store the client and initialize rate-limiting structures
        self.clients[nickname] = client_socket
        self.client_message_timestamps[nickname] = []

        # Send a welcome message and help guide
        welcome_message = f"Welcome to the chatroom! Your nickname is '{nickname}'.\n"
        welcome_message += self.get_help_message()
        client_socket.sendall(welcome_message.encode('utf-8'))

        # Continuously listen for client messages
        while True:
            try:
                client_socket.settimeout(CONNECTION_TIMEOUT)  # Set timeout for connection inactivity
                message = client_socket.recv(MAX_MESSAGE_LENGTH).decode('utf-8')

                # Disconnect the client if the message is empty
                if not message:
                    self.remove_client(nickname, ip)
                    break

                # Enforce rate-limiting for message sending
                if not self.is_within_rate_limit(nickname):
                    self.send_error_message(nickname, "You are sending messages too fast. Please slow down.")
                    continue

                # Process the client's message (commands or text)
                self.process_message(nickname, message)

            except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
                print(f"Client {nickname} from {ip} disconnected.")
                self.remove_client(nickname, ip)
                break

    def process_message(self, nickname, message):
        """Process client messages, handle commands, or broadcast to rooms."""
        if len(message) > MAX_MESSAGE_LENGTH:
            self.send_error_message(nickname, f"Message too long. Max length is {MAX_MESSAGE_LENGTH} characters.")
            return

        # If the message starts with a '/', treat it as a command
        if message.startswith('/'):
            parts = message.split(' ', 1)
            command = parts[0]
            arguments = parts[1] if len(parts) > 1 else ""

            # Handle different commands like joining rooms, sending messages, etc.
            if command == '/join':
                if self.find_user_room(nickname):
                    self.send_error_message(nickname, "You are already in a room. Leave the room before joining another one.")
                else:
                    self.join_room(nickname, arguments)
            elif command == '/leave':
                if not self.find_user_room(nickname):
                    self.send_error_message(nickname, "You are not in any room.")
                else:
                    self.leave_room(nickname)
            elif command == '/msg':
                self.send_private_message(nickname, arguments)
            elif command == '/rooms':
                self.list_rooms(nickname)
            elif command == '/kick':
                self.kick_user_from_room(nickname, arguments)
            elif command == '/admin':
                self.make_room_admin(nickname, arguments)
            elif command == '/unadmin':
                self.unadmin_user(nickname, arguments)
            elif command == '/reclaim':
                self.reclaim_ownership(nickname, arguments)
            elif command == '/help':
                self.send_info_message(nickname, self.get_help_message())
            else:
                self.send_error_message(nickname, "Invalid command.")
        else:
            # Broadcast the message to the room if not a command
            room_name = self.find_user_room(nickname)
            if room_name:
                self.broadcast(room_name, message, sender=nickname)
            else:
                self.send_error_message(nickname, "You are not in any room.")

    def is_within_rate_limit(self, nickname):
        """Check if the client is sending messages within the allowed rate limit."""
        current_time = time.time()
        timestamps = self.client_message_timestamps[nickname]

        # Only keep timestamps within the last 10 seconds
        timestamps = [t for t in timestamps if current_time - t < 10]

        if len(timestamps) < RATE_LIMIT:
            timestamps.append(current_time)
            self.client_message_timestamps[nickname] = timestamps
            return True
        else:
            return False

    def remove_client(self, nickname, ip):
        """Remove a client from the server and any room they are in."""
        if nickname in self.clients:
            del self.clients[nickname]  # Remove client from list of connected users
            if ip and ip in self.client_ips:
                self.client_ips[ip] -= 1  # Decrease IP's connection count

            # Remove client from any room they were in
            room_name = self.find_user_room(nickname)
            if room_name:
                if nickname == self.room_owners.get(room_name):
                    self.room_owners[room_name] = None  # Revoke ownership on disconnect
                if nickname in self.room_admins.get(room_name, []):
                    self.room_admins[room_name].remove(nickname)

                self.rooms[room_name]['clients'].remove(nickname)

            print(f"Client {nickname} removed from the server.")

    def ban_user(self, nickname):
        """Ban a user from the server."""
        if nickname in self.clients:
            print(f"Banning user: {nickname}")
            self.clients[nickname].sendall("You have been banned from the server.".encode('utf-8'))
            self.remove_client(nickname, None)

    def kick_user(self, nickname):
        """Kick a user from the server."""
        if nickname in self.clients:
            print(f"Kicking user: {nickname}")
            self.clients[nickname].sendall("You have been kicked from the server.".encode('utf-8'))
            self.remove_client(nickname, None)

    def announce_message(self, message):
        """Broadcast an announcement to all connected users."""
        for nickname, client_socket in self.clients.items():
            try:
                client_socket.sendall(f"[Announcement]: {message}".encode('utf-8'))
            except:
                pass

    # Additional methods for managing rooms, admins, and private messaging...

if __name__ == "__main__":
    # Ensure the correct usage of the script
    if len(sys.argv) < 2:
        print("Usage: python3 server.py [port]")
        sys.exit(1)

    port = int(sys.argv[1])  # Take port number from the command line
    server = ChatServer(port)  # Initialize the chat server
    server.start()  # Start the server
