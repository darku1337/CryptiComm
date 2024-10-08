# CryptiComm

**CryptiComm** is a decentralized, fully encrypted chatroom system built in Python. It is designed to provide secure, private communication between users. With SSL/TLS encryption, CryptiComm ensures that all messages and interactions are protected, making it perfect for those seeking privacy in their communications. Users can create chatrooms with admin controls, reclaim room ownership via secure tokens, and manage permissions within their rooms.

## Features

- **Decentralized Chatrooms**: Users can join or create chatrooms with customizable admin and owner controls.
- **End-to-End Encryption**: All messages are securely encrypted using SSL/TLS.
- **Room Admins and Owners**: Room owners can promote or demote admins, reclaim ownership using secure tokens, and manage room members.
- **Rate-Limiting and Anti-Spam**: Enforced rate limits to prevent spamming.
- **Private Messaging**: Users can send private messages securely to other users.
- **Cross-Room Announcements**: Server owners can broadcast messages to all connected users.

## Getting Started

### Prerequisites
- Python 3.x
- OpenSSL for generating SSL certificates

### Running the Server

1. Generate SSL certificates (if needed):
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
   ```

2. Start the server:
   ```bash
   python3 server.py [port]
   ```

3. You will now be able to manage the chatroom server from the terminal.

### Running the Client

1. Start the client by connecting to the server:
   ```bash
   python3 client.py [server_host] [server_port]
   ```

2. Once connected, you'll be prompted to enter a nickname and can begin chatting.

## Commands

### Client Commands
- `/join [room_name]` – Join or create a new room.
- `/leave` – Leave the current room.
- `/kick [nickname]` – Kick a user from your room (admin-only).
- `/admin [nickname]` – Promote a user to admin (owner-only).
- `/unadmin [nickname]` – Demote a user from admin (owner-only).
- `/reclaim [token]` – Reclaim room ownership using a secure token.
- `/msg [nickname] [message]` – Send a private message to a user.
- `/rooms` – List all active rooms.
- `/help` – Display the list of available commands.

### Server Commands (Owner Only)
- `list users` – Lists all connected users.
- `ban [nickname]` – Ban a user from the server.
- `kick [nickname]` – Kick a user from the server.
- `announce [message]` – Send an announcement to all users.

## Technology Stack

- **Python 3.x**
- **Networking**: Sockets, SSL/TLS encryption
- **Threading**: Handles multiple connections simultaneously
- **Colorama**: Colorizes terminal output for better readability

## License

This project is licensed under the MIT License – see the LICENSE file for details.
