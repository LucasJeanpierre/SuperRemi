from tools.KDF import KDF
from tools.Cipher import RSA
from tools.Cipher import SerpentCipher
import json
import time

class Conversation:
    def __init__(self, me, other):
        self.me = me
        self.other = other
        self.messages = []


        # Get the chain key, the salt and messages from src/tools/conversation/{me}.json
        try:
            with open(f"src/tools/conversations/{me.username}.json", "r") as f:
                conversations = json.load(f)

                self.chain_key = conversations[self.other.username]['chain_key']
                self.salt = conversations[self.other.username]['salt']

                private_key = me.getPrivateKey()
                rsa = RSA(None, private_key)
                self.chain_key = rsa.decrypt(self.chain_key, key="Private")
                self.salt = rsa.decrypt(self.salt, key="Private")
                    
        except:
            raise Exception("No conversation with this user")
        
        self.kfd = KDF(self.chain_key, self.salt, 256)

        try:
            self.iterations = len(conversations[self.other.username]['messages'])
            for _ in range(self.iterations):
                self.kfd.derive()
        except:
            self.iterations = 0



    @staticmethod
    def create_conversation(me, other, chain_key, salt):
        
        # Encrypt the chain key and the salt with the me's public key
        me_public_key = me.getPublicKey()
        rsa = RSA(me_public_key, None)
        encrypted_chain_key = rsa.encrypt(chain_key, key="Public")
        encrypted_salt = rsa.encrypt(salt, key="Public")

        # Save the conversations in src/tools/conversations/*.json with the other conversations
        # Sender
        try:
            with open(f"src/tools/conversations/{me.username}.json", "r") as f:


                if not other.username in conversations:
                    conversations[other.username] = {
                        'chain_key': encrypted_chain_key,
                        'salt': encrypted_salt
                    }
                    
        except:
            conversations = {}
            conversations[other.username] = {
                'chain_key': encrypted_chain_key,
                'salt': encrypted_salt
            }
        

        with open(f"src/tools/conversations/{me.username}.json", "w") as f:
            json.dump(conversations, f)


        # Encrypt the chain key and the salt with the other user's public key

        other_public_key = other.getPublicKey()
        rsa = RSA(other_public_key, None)
        encrypted_chain_key = rsa.encrypt(chain_key, key="Public")
        encrypted_salt = rsa.encrypt(salt, key="Public")

        # Receiver
        try:
            with open(f"src/tools/conversations/{other.username}.json", "r") as f:
                conversations = json.load(f)

                if not me.username in conversations:
                    conversations[me.username] = {
                        'chain_key': encrypted_chain_key,
                        'salt': encrypted_salt
                    }
                
                    
        except:
            conversations = {}
            conversations[me.username] = {
                'chain_key': encrypted_chain_key,
                'salt': encrypted_salt
            }
        
        

        with open(f"src/tools/conversations/{other.username}.json", "w") as f:
            json.dump(conversations, f)


    def send_message(self, message):
        """
        Sends a message
        :param message: The message to send
        :return: None
        """
        # Encrypt the message
        self.kfd = KDF(self.chain_key, self.salt, 256)
        nb_messages = Conversation.get_number_of_messages(self.me, self.other)
        for _ in range(nb_messages):
            self.kfd.derive()
        secret_key = self.kfd.derive()
        cipher = SerpentCipher(secret_key)
        encrypted_message = cipher.encrypt(message)
        

        # Save the message in src/tools/conversation/{me}.json with the other messages
        Conversation.save_message_in_conversation(self.me, self.other, encrypted_message, owner=self.me)
        Conversation.save_message_in_conversation(self.me, self.other, encrypted_message, owner=self.other)

        return True
    
    def get_messages(self):
        """
        Gets the messages
        :return: The messages
        """
        # Get the messages from src/tools/conversation/{me}.json
        try:
            with open(f"src/tools/conversations/{self.me.username}.json", "r") as f:
                conversations = json.load(f)

                if not self.other.username in conversations:
                    messages = []
                else:
                    try:
                        messages = conversations[self.other.username]['messages']
                    except:
                        messages = []
        except:
            messages = []
        
        # Decrypt the messages
        self.kfd = KDF(self.chain_key, self.salt, 256)

        decrypted_messages = []
        for message in messages:
            decrypted_message = SerpentCipher(self.kfd.derive()).decrypt(message['message'])
            decrypted_messages.append({
                'id': message['id'],
                'sender': message['sender'],
                'message': decrypted_message,
                'time': message['time']
            })
        
        return decrypted_messages


    @staticmethod
    def save_message_in_conversation(sender, receiver, message, owner):
        """
        Saves a message in a conversation
        :param me: The user
        :param other: The other user
        :param message: The message
        :return: None
        """
        other = sender if owner is not sender else receiver
        # Save the message in src/tools/conversation/{me}.json with the other messages
        try:
            with open(f"src/tools/conversations/{owner.username}.json", "r") as f:
                conversations = json.load(f)

                if not other.username in conversations:
                    messages = []
                else:
                    try:
                        messages = conversations[other.username]['messages']
                    except:
                        messages = []

                messages.append({
                    'id': len(messages)+1,
                    'sender': sender.username,
                    'message': message,
                    'time': time.time()
                })

                conversations[other.username] = {
                    'chain_key': conversations[other.username]['chain_key'],
                    'salt': conversations[other.username]['salt'],
                    'messages': messages
                }
        except Exception as e:
            raise Exception("No conversation with this user")
        

        with open(f"src/tools/conversations/{owner.username}.json", "w") as f:
            json.dump(conversations, f)
        

    @staticmethod
    def get_number_of_messages(me, other):
        """
        Gets the number of messages
        :param me: The user
        :param other: The other user
        :return: The number of messages
        """
        # Get the messages from src/tools/conversation/{me}.json
        try:
            with open(f"src/tools/conversations/{me.username}.json", "r") as f:
                conversations = json.load(f)
            iterations = len(conversations[other.username]['messages'])
        except:
            iterations = 0

        return iterations


    

   