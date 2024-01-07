from tools.Hash import sha256
import time
import random
import string

class Block:
    def __init__(self, index, timestamp, user, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.user = user
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        data_str = str(self.index) + str(self.timestamp) + str(self.user) + str(self.data) + str(self.previous_hash) + str(self.nonce)
        return sha256(data_str.encode())

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), "GS15", "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, user, data):
        latest_block = self.get_latest_block()
        new_block = Block(len(self.chain), time.time(), user, data, latest_block.hash)

        # Proof of Work
        new_block = self.proof_of_work(new_block)

        self.chain.append(new_block)

    def proof_of_work(self, block, difficulty=2):
        while block.hash[:difficulty] != "0" * difficulty:
            block.nonce = "".join([random.choice(string.ascii_letters) for _ in range(32)])
            block.hash = block.calculate_hash()
        return block

    def print(self):
        for block in self.chain:
            print(f"Index: {block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"User: {block.user}")
            print(f"Data: {block.data}")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Nonce: {block.nonce}")
            print(f"Hash: {block.hash}")
            print("-" * 30)