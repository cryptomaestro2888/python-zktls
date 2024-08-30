from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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