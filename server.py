import socket
import threading
import sys
import ssl
import datetime
import time
import secrets

MAX_MESSAGE_LENGTH = 1024
MAX_NICKNAME_LENGTH = 32
MAX_CONNECTIONS_PER_IP = 5
RATE_LIMIT = 5
CONNECTION_TIMEOUT = 3600  # 1hr till timeout


class ChatServer:
    def __init__(self, port):
        self.host = 'localhost'
        self.port = port
        self.rooms = {}
        self.clients = {}
        self.client_message_timestamps = {}
        self.client_ips = {}
        self.room_admins = {}
        self.room_owners = {}
        self.owner_tokens = {}  # Store owner tokens for each room
        self.passwords = {}  # Store room passwords

    def generate_owner_token(self):
        """Generate a secure random token for room ownership."""
        return secrets.token_hex(16)

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
        except socket.error as e:
            print(f"Failed to bind on port {self.port}: {e}")
            sys.exit(1)

        server_socket.listen(5)
        print(f"Server started on port {self.port}")

        owner_thread = threading.Thread(target=self.server_owner_commands)
        owner_thread.start()

        while True:
            try:
                client_socket, client_address = server_socket.accept()
                ip = client_address[0]
                print(f"New connection from {ip}:{client_address[1]}")

                if self.client_ips.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
                    print(f"Rejected connection from {ip}: too many connections.")
                    client_socket.close()
                    continue

                self.client_ips[ip] = self.client_ips.get(ip, 0) + 1

                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.load_cert_chain(certfile='server.crt', keyfile='server.key')
                client_socket = context.wrap_socket(client_socket, server_side=True)

                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                client_thread.start()
            except (KeyboardInterrupt, SystemExit):
                print("Server shutting down...")
                break

        server_socket.close()

    def server_owner_commands(self):
        """Allows server owner to issue commands."""
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
        ip = client_address[0]

        while True:
            client_socket.sendall(f"Enter your nickname (max {MAX_NICKNAME_LENGTH} characters): ".encode('utf-8'))
            nickname = client_socket.recv(1024).decode('utf-8').strip()

            if len(nickname) > MAX_NICKNAME_LENGTH:
                client_socket.sendall(f"Nickname too long. Maximum length is {MAX_NICKNAME_LENGTH} characters. Please pick a shorter nickname.\n".encode('utf-8'))
                continue

            # Check if the nickname already exists (for reconnection)
            if nickname in self.clients:
                client_socket.sendall(f"Nickname '{nickname}' is already taken. Please choose a different nickname.\n".encode('utf-8'))
                continue

            break

        self.clients[nickname] = client_socket
        self.client_message_timestamps[nickname] = []

        welcome_message = f"Welcome to the chatroom! Your nickname is '{nickname}'.\n"
        welcome_message += self.get_help_message()
        client_socket.sendall(welcome_message.encode('utf-8'))

        while True:
            try:
                client_socket.settimeout(CONNECTION_TIMEOUT)
                message = client_socket.recv(MAX_MESSAGE_LENGTH).decode('utf-8')

                if not message:
                    self.remove_client(nickname, ip)
                    break

                if not self.is_within_rate_limit(nickname):
                    self.send_error_message(nickname, "You are sending messages too fast. Please slow down.")
                    continue

                self.process_message(nickname, message)

            except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
                print(f"Client {nickname} from {ip} disconnected.")
                self.remove_client(nickname, ip)
                break

    def process_message(self, nickname, message):
        if len(message) > MAX_MESSAGE_LENGTH:
            self.send_error_message(nickname, f"Message too long. Max length is {MAX_MESSAGE_LENGTH} characters.")
            return

        if message.startswith('/'):
            parts = message.split(' ', 1)
            command = parts[0]
            arguments = parts[1] if len(parts) > 1 else ""

            if command == '/join':
                self.join_room(nickname, arguments)
            elif command == '/leave':
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
            elif command == '/setpassword':
                self.set_room_password(nickname, arguments)
            elif command == '/help':
                self.send_info_message(nickname, self.get_help_message())
            else:
                self.send_error_message(nickname, "Invalid command.")
        else:
            room_name = self.find_user_room(nickname)
            if room_name:
                self.broadcast(room_name, message, sender=nickname)
            else:
                self.send_error_message(nickname, "You are not in any room.")

    def is_within_rate_limit(self, nickname):
        current_time = time.time()
        timestamps = self.client_message_timestamps[nickname]

        timestamps = [t for t in timestamps if current_time - t < 10]

        if len(timestamps) < RATE_LIMIT:
            timestamps.append(current_time)
            self.client_message_timestamps[nickname] = timestamps
            return True
        else:
            return False

    def remove_client(self, nickname, ip):
        """Removes a client from the server and any room they are in."""
        if nickname in self.clients:
            del self.clients[nickname]
            if ip and ip in self.client_ips:
                self.client_ips[ip] -= 1

            room_name = self.find_user_room(nickname)
            if room_name:
                if nickname == self.room_owners.get(room_name):
                    self.room_owners[room_name] = None  # Revoke ownership on disconnect
                if nickname in self.room_admins.get(room_name, []):
                    self.room_admins[room_name].remove(nickname)

                self.rooms[room_name]['clients'].remove(nickname)

            print(f"Client {nickname} removed from the server.")

    def ban_user(self, nickname):
        if nickname in self.clients:
            print(f"Banning user: {nickname}")
            self.clients[nickname].sendall("You have been banned from the server.".encode('utf-8'))
            self.remove_client(nickname, None)

    def kick_user(self, nickname):
        if nickname in self.clients:
            print(f"Kicking user: {nickname}")
            self.clients[nickname].sendall("You have been kicked from the server.".encode('utf-8'))
            self.remove_client(nickname, None)

    def announce_message(self, message):
        for nickname, client_socket in self.clients.items():
            try:
                client_socket.sendall(f"[Announcement]: {message}".encode('utf-8'))
            except:
                pass

    def join_room(self, nickname, arguments):
        if not arguments.strip():
            self.send_error_message(nickname, "Room name cannot be empty.")
            return

        parts = arguments.split(' ')
        room_name = parts[0]
        password = parts[1] if len(parts) > 1 else None

        if room_name in self.passwords and self.passwords[room_name] and self.passwords[room_name] != password:
            self.send_error_message(nickname, "Incorrect password for the room.")
            return

        if room_name not in self.rooms:
            # Generate owner token for the first user
            token = self.generate_owner_token()
            self.rooms[room_name] = {'clients': []}
            self.room_admins[room_name] = [nickname]
            self.room_owners[room_name] = nickname
            self.owner_tokens[room_name] = token  # Store the token
            self.passwords[room_name] = None  # No password by default
            self.send_info_message(nickname, f"You are the owner of room '{room_name}'. Your token is: {token}")

        if nickname not in self.rooms[room_name]['clients']:
            self.rooms[room_name]['clients'].append(nickname)
            self.broadcast(room_name, f"{nickname} joined the room.", sender=nickname)

            notification_message = f"You have successfully joined the room '{room_name}'."
            self.clients[nickname].sendall(notification_message.encode('utf-8'))
        else:
            self.send_error_message(nickname, f"You are already in the room '{room_name}'.")

    def reclaim_ownership(self, nickname, token):
        """Reclaim room ownership if the user provides the correct token."""
        room_name = self.find_user_room(nickname)
        if room_name:
            if room_name in self.owner_tokens and self.owner_tokens[room_name] == token:
                self.room_owners[room_name] = nickname  # Restore ownership
                self.send_info_message(nickname, f"Welcome back, {nickname}. You are now the owner of '{room_name}'.")
            else:
                self.send_error_message(nickname, "Invalid token. You cannot reclaim ownership.")
        else:
            self.send_error_message(nickname, "You are not in any room.")

    def leave_room(self, nickname):
        room_name = self.find_user_room(nickname)
        if room_name:
            self.rooms[room_name]['clients'].remove(nickname)
            self.broadcast(room_name, f"{nickname} left the room.", sender=nickname)

    def kick_user_from_room(self, admin_nickname, target_nickname):
        room_name = self.find_user_room(admin_nickname)
        if room_name:
            if admin_nickname == self.room_owners[room_name] or (target_nickname not in self.room_admins[room_name]):
                if target_nickname in self.rooms[room_name]['clients']:
                    self.rooms[room_name]['clients'].remove(target_nickname)
                    self.broadcast(room_name, f"{target_nickname} was kicked by {admin_nickname}.", sender=admin_nickname)
                else:
                    self.send_error_message(admin_nickname, f"{target_nickname} is not in the room.")
            else:
                self.send_error_message(admin_nickname, "You cannot kick another admin.")
        else:
            self.send_error_message(admin_nickname, "You are not an admin of this room.")

    def make_room_admin(self, admin_nickname, target_nickname):
        room_name = self.find_user_room(admin_nickname)
        if room_name:
            if admin_nickname == self.room_owners[room_name]:
                if target_nickname in self.rooms[room_name]['clients']:
                    self.room_admins[room_name].append(target_nickname)
                    self.broadcast(room_name, f"{target_nickname} is now an admin.", sender=admin_nickname)
                else:
                    self.send_error_message(admin_nickname, f"{target_nickname} is not in the room.")
            else:
                self.send_error_message(admin_nickname, "Only the room owner can assign admins.")
        else:
            self.send_error_message(admin_nickname, "You are not in any room.")

    def unadmin_user(self, admin_nickname, target_nickname):
        room_name = self.find_user_room(admin_nickname)
        if room_name:
            if admin_nickname == self.room_owners[room_name]:
                if target_nickname in self.room_admins[room_name]:
                    if target_nickname != self.room_owners[room_name]:  # Cannot unadmin the owner
                        self.room_admins[room_name].remove(target_nickname)
                        self.broadcast(room_name, f"{target_nickname} is no longer an admin.", sender=admin_nickname)
                    else:
                        self.send_error_message(admin_nickname, "You cannot unadmin the room owner.")
                else:
                    self.send_error_message(admin_nickname, f"{target_nickname} is not an admin.")
            else:
                self.send_error_message(admin_nickname, "Only the room owner can unadmin users.")
        else:
            self.send_error_message(admin_nickname, "You are not in any room.")

    def set_room_password(self, nickname, arguments):
        """Allow the room owner to set or remove a password for their room."""
        room_name = self.find_user_room(nickname)
        if room_name:
            if nickname == self.room_owners[room_name]:
                if arguments.strip():
                    self.passwords[room_name] = arguments
                    self.send_info_message(nickname, f"Password for room '{room_name}' set.")
                else:
                    self.passwords[room_name] = None
                    self.send_info_message(nickname, f"Password for room '{room_name}' removed.")
            else:
                self.send_error_message(nickname, "Only the room owner can set a password.")
        else:
            self.send_error_message(nickname, "You are not in any room.")

    def send_private_message(self, sender, message):
        parts = message.split(' ', 1)
        recipient = parts[0]
        text = parts[1] if len(parts) > 1 else ""

        if recipient in self.clients:
            recipient_socket = self.clients[recipient]
            private_message = f"[Private from {sender}]: {text}"
            recipient_socket.sendall(private_message.encode('utf-8'))
        else:
            self.send_error_message(sender, f"User '{recipient}' is not online.")

    def list_rooms(self, nickname):
        if self.rooms:
            room_list = "Active rooms:\n"
            for room_name in self.rooms:
                room_list += f"- {room_name} ({len(self.rooms[room_name]['clients'])} members)\n"
            self.send_info_message(nickname, room_list)
        else:
            self.send_info_message(nickname, "No active rooms.")

    def broadcast(self, room_name, message, sender=None):
        if room_name in self.rooms:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Check if the sender is an admin or owner and add a crown if applicable
            crown = ""
            if sender == self.room_owners.get(room_name):
                crown = "**"
            elif sender in self.room_admins.get(room_name, []):
                crown = "*"

            full_message = f"{timestamp} [{room_name}] {crown}{sender}: {message}"
            print(f"Broadcasting message '{message}' to room '{room_name}'")
            clients_to_remove = []
            for client in self.rooms[room_name]['clients']:
                try:
                    if client != sender:
                        print(f"Sending message to client '{client}'")
                        self.clients[client].sendall(full_message.encode('utf-8'))
                except socket.error:
                    print(f"Failed to send message to client '{client}'. Removing from room.")
                    clients_to_remove.append(client)

            for client in clients_to_remove:
                self.rooms[room_name]['clients'].remove(client)

    def send_info_message(self, nickname, message):
        if nickname in self.clients:
            self.clients[nickname].sendall(f"[INFO]: {message}".encode('utf-8'))

    def send_error_message(self, nickname, message):
        if nickname in self.clients:
            self.clients[nickname].sendall(f"[ERROR]: {message}".encode('utf-8'))

    def find_user_room(self, nickname):
        for room_name, room in self.rooms.items():
            if nickname in room['clients']:
                return room_name
        return None

    def get_help_message(self):
        return (
            "Commands:\n"
            "/join [room_name] [password] - Join a room (creates one if it doesn't exist, use password if applicable)\n"
            "/leave - Leave your current room\n"
            "/kick [nickname] - Kick a user from your room (admin only)\n"
            "/admin [nickname] - Promote a user to admin (room owner only)\n"
            "/unadmin [nickname] - Demote an admin (room owner only)\n"
            "/reclaim [token] - Reclaim room ownership using your token\n"
            "/setpassword [password] - Set or remove password for your room (room owner only)\n"
            "/msg [nickname] [message] - Send a private message to a user\n"
            "/rooms - List all active rooms\n"
            "/help - Show this help message\n"
        )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 server.py [port]")
        sys.exit(1)

    port = int(sys.argv[1])
    server = ChatServer(port)
    server.start()
