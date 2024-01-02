from tools.KDF import KDF
from tools.Cipher import SerpentCipher
import json
import time

class Conversation:
    def __init__(self, me, other, chain_key, salt):
        self.me = me
        self.other = other
        self.chain_key = chain_key
        self.salt = salt
        self.messages = []
        self.kfd = KDF(self.chain_key, self.salt, 256)

        # Save the conversations in src/tools/conversations/*.json with the other conversations
        # Sender
        try:
            with open(f"src/tools/conversations/{me.username}.json", "r") as f:
                conversations = json.load(f)
                
                if not self.other.username in conversations:
                    conversations[self.other.username] = {
                        'chain_key': self.chain_key,
                        'salt': self.salt
                    }
                    
        except:
            conversations = {}
            conversations[self.other.username] = {
                'chain_key': self.chain_key,
                'salt': self.salt
            }
        

        with open(f"src/tools/conversations/{me.username}.json", "w") as f:
            json.dump(conversations, f)


        # Receiver
        try:
            with open(f"src/tools/conversations/{other.username}.json", "r") as f:
                conversations = json.load(f)

                if not self.me.username in conversations:
                    conversations[self.me.username] = {
                        'chain_key': self.chain_key,
                        'salt': self.salt
                    }
                    
        except:
            conversations = {}
            conversations[self.me.username] = {
                'chain_key': self.chain_key,
                'salt': self.salt
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
        secret_key = self.kfd.derive()
        cipher = SerpentCipher(secret_key)

        encrypted_message = cipher.encrypt(message)

        # Save the message in src/tools/conversation/{me}.json with the other messages
        Conversation.save_message_in_conversation(self.me, self.other, encrypted_message, owner=self.me)
        Conversation.save_message_in_conversation(self.me, self.other, encrypted_message, owner=self.other)


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
        

        


    

   