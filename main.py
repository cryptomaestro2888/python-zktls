import sys
import socket
from tls_handshake import TLSHandshake
from secure_communication import secure_communication

def run_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('localhost', 12345))
        handshake = TLSHandshake(is_client=True)
        write_key, read_key, iv = handshake.perform_handshake(sock)
        secure_communication(sock, write_key, read_key, iv)
    finally:
        sock.close()

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server listening on port 12345")
    
    while True:
        client_sock, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        try:
            handshake = TLSHandshake(is_client=False)
            read_key, write_key, iv = handshake.perform_handshake(client_sock)
            secure_communication(client_sock, write_key, read_key, iv)
        finally:
            client_sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['client', 'server']:
        print("Usage: python main.py [client|server]")
        sys.exit(1)
    
    if sys.argv[1] == 'client':
        run_client()
    else:
        run_server()