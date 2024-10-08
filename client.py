import socket
import threading
import sys
import ssl
from colorama import init, Fore, Style

init()

class ChatClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port

    def start(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket = ssl.wrap_socket(self.client_socket, ssl_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_NONE)
            self.client_socket.connect((self.server_host, self.server_port))
            self.nickname = None
            print(Fore.GREEN + "Connected to the server." + Style.RESET_ALL)
            self.receive_messages_thread = threading.Thread(target=self.receive_messages)
            self.receive_messages_thread.start()
            self.send_messages()
        except ConnectionRefusedError:
            print(Fore.RED + f"Connection refused. Make sure the server is running on {self.server_host}:{self.server_port}." + Style.RESET_ALL)

    def send_messages(self):
        while True:
            try:
                message = input()
                self.client_socket.sendall(message.encode('utf-8'))
            except (KeyboardInterrupt, SystemExit):
                self.disconnect()
                break

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    print(Fore.CYAN + message + Style.RESET_ALL)
                else:
                    self.disconnect()
                    break
            except ConnectionResetError:
                print(Fore.RED + "Connection to the server lost." + Style.RESET_ALL)
                self.disconnect()
                break

    def disconnect(self):
        self.client_socket.close()
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(Fore.YELLOW + "Usage: python3 client.py [server_host] [server_port]" + Style.RESET_ALL)
        sys.exit(1)

    server_host = sys.argv[1]
    server_port = int(sys.argv[2])

    client = ChatClient(server_host, server_port)
    client.start()
