from tools.Hash import hmac_sha256
import bitarray
import string
import random

class KDF():
    """
    Key derivation function
    """
    def __init__(self, chain_key, salt, length):
        self.chain_key = chain_key
        self.salt = salt
        self.length = length
        self.iteration = 0

    def __str__(self) -> str:
        return f"KDF(chain_key={self.chain_key}, salt={self.salt}, iteration={self.iteration})"


    def derive(self):
        # Message key derivation
        content = str(self.chain_key) + str(self.salt) + str(self.iteration)
        message_key = hmac_sha256(self.chain_key.encode(), content.encode())

        # Chain key derivation
        content = str(self.salt) + str(self.chain_key) + str(self.iteration)
        self.chain_key = hmac_sha256(self.chain_key.encode(), content.encode())

        self.iteration += 1

        bt = bitarray.bitarray()
        bt.frombytes(message_key.encode())

        return bt.to01()[:self.length]
    
    @staticmethod
    def generate_salt():
        return "".join([random.choice(string.ascii_letters) for _ in range(16)])
    
    @staticmethod
    def generate_chain_key():
        return "".join([random.choice(string.ascii_letters) for _ in range(32)])
        

