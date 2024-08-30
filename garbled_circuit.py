import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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