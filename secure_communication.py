import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

def secure_communication(sock, write_key, read_key, iv):
    def encrypt(data):
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(write_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag

    def decrypt(data):
        nonce, ciphertext, tag = data[:12], data[12:-16], data[-16:]
        cipher = Cipher(algorithms.AES(read_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    while True:
        try:
            message = input("Enter message: ").encode()
            encrypted_message = encrypt(message)
            sock.sendall(encrypted_message)

            received_data = sock.recv(4096)
            decrypted_message = decrypt(received_data)
            print(f"Received: {decrypted_message.decode()}")
        except InvalidSignature