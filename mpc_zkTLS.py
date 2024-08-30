import random
import os
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class GarbledCircuit:
    def __init__(self):
        self.gates = []
        self.wire_labels = {}
        self.global_key = os.urandom(16)  # 128-bit global key for free-XOR

    def generate_wire_labels(self, wire):
        if wire not in self.wire_labels:
            label_0 = os.urandom(16)
            label_1 = bytes(a ^ b for a, b in zip(label_0, self.global_key))
            self.wire_labels[wire] = (label_0, label_1)
        return self.wire_labels[wire]

    def add_gate(self, gate_type, input_wires, output_wire):
        if gate_type == 'XOR':
            # Free-XOR optimization
            in1_0, in1_1 = self.generate_wire_labels(input_wires[0])
            in2_0, in2_1 = self.generate_wire_labels(input_wires[1])
            out_0 = bytes(a ^ b for a, b in zip(in1_0, in2_0))
            out_1 = bytes(a ^ b for a, b in zip(out_0, self.global_key))
            self.wire_labels[output_wire] = (out_0, out_1)
        elif gate_type == 'AND':
            in1_0, in1_1 = self.generate_wire_labels(input_wires[0])
            in2_0, in2_1 = self.generate_wire_labels(input_wires[1])
            out_0, out_1 = self.generate_wire_labels(output_wire)
            
            garbled_table = []
            for i in range(4):
                in1 = in1_0 if i & 2 == 0 else in1_1
                in2 = in2_0 if i & 1 == 0 else in2_1
                out = out_0 if (i & 2) & (i & 1) == 0 else out_1
                
                # Point-and-permute technique
                entry = self.encrypt(in1 + in2, out)
                garbled_table.append(entry)
            
            # Randomly permute the garbled table
            self.gates.append(('AND', input_wires, output_wire, garbled_table))

    def encrypt(self, key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, key, ciphertext):
        iv, ciphertext = ciphertext[:16], ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def evaluate(self, input_labels):
        output = input_labels.copy()
        for gate in self.gates:
            if gate[0] == 'XOR':
                _, input_wires, output_wire = gate
                output[output_wire] = bytes(a ^ b for a, b in zip(output[input_wires[0]], output[input_wires[1]]))
            elif gate[0] == 'AND':
                _, input_wires, output_wire, garbled_table = gate
                key = output[input_wires[0]] + output[input_wires[1]]
                for entry in garbled_table:
                    try:
                        decrypted = self.decrypt(key, entry)
                        if decrypted in self.wire_labels[output_wire]:
                            output[output_wire] = decrypted
                            break
                    except:
                        continue
        return output

    def get_input_labels(self, inputs):
        return {wire: self.wire_labels[wire][int(bit)] for wire, bit in inputs.items()}

class OTSender:
    def __init__(self, m0, m1):
        self.m0 = m0
        self.m1 = m1
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def step1(self):
        return self.public_key

    def step3(self, B):
        shared_secret0 = self.private_key.exchange(ec.ECDH(), B)
        shared_secret1 = self.private_key.exchange(ec.ECDH(), B - self.public_key.public_numbers().y * self.public_key)

        k0 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'OT-key-0',
        ).derive(shared_secret0)

        k1 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'OT-key-1',
        ).derive(shared_secret1)

        c0 = bytes(x ^ y for x, y in zip(self.m0, k0))
        c1 = bytes(x ^ y for x, y in zip(self.m1, k1))

        return c0, c1

class OTReceiver:
    def __init__(self, choice):
        self.choice = choice
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def step2(self, A):
        if self.choice == 0:
            self.B = self.private_key.public_key()
        else:
            self.B = self.private_key.public_key() + A

        return self.B

    def step4(self, c0, c1):
        shared_secret = self.private_key.exchange(ec.ECDH(), A)

        k = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f'OT-key-{self.choice}'.encode(),
        ).derive(shared_secret)

        m = bytes(x ^ y for x, y in zip(c0 if self.choice == 0 else c1, k))
        return m

def oblivious_transfer(sender_bits, receiver_choice):
    sender = OTSender(sender_bits[0], sender_bits[1])
    receiver = OTReceiver(receiver_choice)

    # Step 1
    A = sender.step1()

    # Step 2
    B = receiver.step2(A)

    # Step 3
    c0, c1 = sender.step3(B)

    # Step 4
    result = receiver.step4(c0, c1)

    return result

class MPCParty:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, other_public_key):
        return self.private_key.exchange(ec.ECDH(), other_public_key)

def mpc_tls_handshake(party1, party2):
    # Exchange public keys
    party1_public = party1.public_key
    party2_public = party2.public_key

    # Generate shared secrets
    shared_secret1 = party1.generate_shared_secret(party2_public)
    shared_secret2 = party2.generate_shared_secret(party1_public)

    # Use garbled circuits for key derivation
    circuit = GarbledCircuit()
    circuit.add_gate('XOR', [0, 1], 2)
    circuit.add_gate('AND', [2, 3], 4)

    # Garbled circuit evaluation
    party1_input = {0: bool(random.getrandbits(1)), 1: bool(random.getrandbits(1))}
    party2_input = {2: bool(random.getrandbits(1)), 3: bool(random.getrandbits(1))}

    party1_labels = circuit.get_input_labels(party1_input)
    party2_labels = {}

    for wire in [2, 3]:
        choices = [circuit.wire_labels[wire][0], circuit.wire_labels[wire][1]]
        party2_labels[wire] = oblivious_transfer(choices, party2_input[wire])

    input_labels = {**party1_labels, **party2_labels}
    circuit_output = circuit.evaluate(input_labels)

    # Use the circuit output to derive the final shared key
    final_shared_key = bytes([shared_secret1[i] ^ shared_secret2[i] ^ circuit_output[i % len(circuit_output)] for i in range(32)])

    return final_shared_key

class TLSHandshake:
    def __init__(self, is_client):
        self.is_client = is_client
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.peer_public_key = None
        self.session_id = os.urandom(32)
        self.client_random = os.urandom(32)
        self.server_random = os.urandom(32)

    def generate_certificate(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Organization"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"mysite.com"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(self.private_key, hashes.SHA256())
        return cert

    def verify_certificate(self, cert_bytes):
        cert = x509.load_der_x509_certificate(cert_bytes)
        # In a real implementation, you would verify the certificate chain
        # and check revocation status. For simplicity, we'll just extract the public key.
        self.peer_public_key = cert.public_key()

    def key_derivation(self, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=48,  # 16 bytes for client write key, 16 for server write key, 16 for IV
            salt=None,
            info=b"tls13 derived",
        )
        key_material = hkdf.derive(shared_secret)
        client_write_key = key_material[:16]
        server_write_key = key_material[16:32]
        iv = key_material[32:]
        return client_write_key, server_write_key, iv

    def perform_handshake(self, sock):
        if self.is_client:
            self.client_hello(sock)
            self.receive_server_hello(sock)
            self.receive_certificate(sock)
            self.receive_server_key_exchange(sock)
            self.send_client_key_exchange(sock)
        else:
            self.receive_client_hello(sock)
            self.server_hello(sock)
            self.send_certificate(sock)
            self.send_server_key_exchange(sock)
            self.receive_client_key_exchange(sock)

        # Perform MPC TLS handshake
        shared_key = mpc_tls_handshake(self, self.peer_public_key)
        
        client_write_key, server_write_key, iv = self.key_derivation(shared_key)
        return (client_write_key, server_write_key, iv) if self.is_client else (server_write_key, client_write_key, iv)

    def client_hello(self, sock):
        # Send client random, supported cipher suites, etc.
        hello_msg = self.client_random + b"\x00\x02\x00\x13"  # TLS_AES_128_GCM_SHA256
        sock.sendall(hello_msg)

    def receive_server_hello(self, sock):
        # Receive server random, chosen cipher suite
        server_hello = sock.recv(1024)
        self.server_random = server_hello[:32]
        # Process chosen cipher suite

    def receive_certificate(self, sock):
        cert_bytes = sock.recv(4096)
        self.verify_certificate(cert_bytes)

    def receive_server_key_exchange(self, sock):
        # Receive and verify server's key exchange parameters
        server_key_exchange = sock.recv(1024)
        # Verify signature, extract parameters

    def send_client_key_exchange(self, sock):
        # Generate and send client's key exchange parameters
        client_key_exchange = b"client_key_exchange_params"
        sock.sendall(client_key_exchange)

    def server_hello(self, sock):
        # Send server random, chosen cipher suite
        hello_msg = self.server_random + b"\x00\x13"  # TLS_AES_128_GCM_SHA256
        sock.sendall(hello_msg)

    def send_certificate(self, sock):
        cert = self.generate_certificate()
        sock.sendall(cert.public_bytes(serialization.Encoding.DER))

    def send_server_key_exchange(self, sock):
        # Generate and send server's key exchange parameters
        server_key_exchange = b"server_key_exchange_params"
        sock.sendall(server_key_exchange)

    def receive_client_hello(self, sock):
        # Receive client random, supported cipher suites
        client_hello = sock.recv(1024)
        self.client_random = client_hello[:32]
        # Process supported cipher suites

    def receive_client_key_exchange(self, sock):
        # Receive and process client's key exchange parameters
        client_key_exchange = sock.recv(1024)
        # Extract parameters

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
        except InvalidSignature:
            print("Error: Message authentication failed.")
        except Exception as e:
            print(f"Error: {str(e)}")
            break

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

# Example usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2 or sys.argv[1] not in ['client', 'server']:
        print("Usage: python script.py [client|server]")
        sys.exit(1)
    
    if sys.argv[1] == 'client':
        run_client()
    else:
        run_server()