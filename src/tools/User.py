from tools.Cipher import RSA
from tools.Conversation import Conversation
import json
import time
import os
import random

class User():

    def __init__(self, username: str):
        self.username = username
        
        # Get keys from src/tools/keys/public.json and src/tools/keys/
        try:
            with open("src/tools/keys/public.json", "r") as f:
                self.public_key = tuple(json.load(f)[self.username])
            with open("src/tools/keys/private.json", "r") as f:
                self.private_key = tuple(json.load(f)[self.username])
        except:
            raise ValueError("User not found")

    def __str__(self):
        return f'{self.username}'
    
    def setConversation(self, conversation):
        self.conversation = conversation

    def getPublicKey(self):
        return self.public_key

    def getPrivateKey(self):
        return self.private_key
    
    def getProof(self):
        rsa = RSA(self.public_key, self.private_key)
        return rsa.generateGillouQuisquaterValue()

    def getUsername(self):
        return self.username
    
    def getCertificate(self):
        # Get certificate from src/tools/keys/certificates.json
        try:
            with open("src/tools/keys/certificates.json", "r") as f:
                certificates = json.load(f)
        except:
            raise ValueError("No certificate found")
        
        if self.username not in certificates:
            raise ValueError("No certificate found")
        
        return certificates[self.username]
    
    def send_message_conversation(self, message):
        """
        Sends a message to the other user
        :param message: The message to be sent
        :return: None
        """
        self.conversation.send_message(message)
        
        return True
    
    def get_messages_conversation(self):
        """
        Gets the messages from the conversation
        :return: The messages
        """
        return self.conversation.get_messages()
    
    def send_message_asymetric(self, message, recipient_name):
        """
        Sends a message to a recipient
        :param message: The message to be sent
        :param recipient: The recipient of the message
        :return: None
        """

        cipher = RSA(self.public_key, self.private_key)
        encrypted_message = cipher.encrypt(message, key="Private")
        recipient = User(recipient_name)
        recipient.receive_message_asymetric(encrypted_message, self.username)
        
        return True
        

    def receive_message_asymetric(self, message, sender):
        # Save the message in src/tools/messagesbox/username.json
        try:
            with open(f"src/tools/messagesbox/{self.username}.json", "r") as f:
                messages = json.load(f)
        except:
            messages = {}
        id = f"{len(messages)+1}"
        content = {
            "sender": sender,
            "time": time.time(),
            "message": message
        }
        messages[id] = content
        with open(f"src/tools/messagesbox/{self.username}.json", "w+") as f:
            json.dump(messages, f)

        return True
    
    def get_messages_asymetric(self):
        # Get messages from src/tools/messagesbox/username.json
        try:
            with open(f"src/tools/messagesbox/{self.username}.json", "r") as f:
                messages = json.load(f)
        except:
            messages = {}
        
        for message_id in messages:
            message = messages[message_id]['message']
            sender = User(messages[message_id]['sender'])
            sent_time = messages[message_id]['time']
            

            cipher = RSA(sender.getPublicKey(), None)
            message = cipher.decrypt(message, key="Public")

            # Time format : 2021-03-31 15:00:00
            sent_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(sent_time))
            
            messages[message_id]['message'] = message
            messages[message_id]['sender'] = sender
            messages[message_id]['time'] = sent_time

        return messages
        
    
    def ask_for_proof_of_knowledge(self, recipient_name):
        """
        Ask for a proof of knowledge
        :param recipient: The recipient of the message
        :return: None
        """

        recipient = User(recipient_name)
        c = random.randrange(1,pow(2, 256))
        return recipient.send_proof_of_knowledge(self.username, c)
        
    
    def send_proof_of_knowledge(self, applicant_name, c):
        """
        Sends a proof of knowledge
        :param recipient: The recipient of the message
        :param c: The proof of complete
        :return: None
        """

        applicant = User(applicant_name)
        y = random.randrange(1,pow(2, 256))
        Y = pow(y, self.public_key[1], self.public_key[0])
        z = (y * pow(self.private_key[1], c, self.private_key[0])) % self.private_key[0]

        return applicant.check_proof_of_knowledge(self.username, Y, z, c)


    def check_proof_of_knowledge(self, recipient_name, Y, z, c):
        """
        Checks a proof of knowledge
        :param recipient: The recipient of the message
        :param Y, z, c: The needed values for the proof
        :return: None
        """

        recipient = User(recipient_name)
        value1 = pow(z, recipient.public_key[1], recipient.public_key[0])
        value2 = (Y * pow(recipient.getProof(), c, recipient.getPublicKey()[0])) % recipient.getPublicKey()[0]

        if value1 == value2:
            return True
        else:
            return False
    


    @staticmethod
    def create_user(username: str, keys=None):
        """
        Creates a user
        :param username: The username of the user
        :param keys: The keys of the user (optional)
        :return: The user
        """
        # Get keys from src/tools/keys/public.json and src/tools/keys/
        try:
            with open("src/tools/keys/public.json", "r") as f:
                public_keys = json.load(f)
            with open("src/tools/keys/private.json", "r") as f:
                private_keys = json.load(f)
        except:
            raise ValueError("No keys found")

        if username in public_keys:
            raise ValueError("User already exists")
        
        if not keys:
            keys = RSA.keyGen()

        public_keys[username] = keys[0]
        private_keys[username] = keys[1]

        with open("src/tools/keys/public.json", "w") as f:
            json.dump(public_keys, f)
        with open("src/tools/keys/private.json", "w") as f:
            json.dump(private_keys, f)

        return keys


    @staticmethod
    def delete_user(username: str):
        """
        Deletes a user
        :param username: The username of the user
        :return: None
        """
        # Remove keys from src/tools/keys/public.json and src/tools/keys/
        try:
            with open("src/tools/keys/public.json", "r") as f:
                public_keys = json.load(f)
            with open("src/tools/keys/private.json", "r") as f:
                private_keys = json.load(f)
        except:
            raise ValueError("No keys found")

        if username not in public_keys:
            raise ValueError("User does not exist")

        del public_keys[username]
        del private_keys[username]

        with open("src/tools/keys/public.json", "w") as f:
            json.dump(public_keys, f)
        with open("src/tools/keys/private.json", "w") as f:
            json.dump(private_keys, f)

        
        # Remove certificate from src/tools/keys/certificates.json
        try:
            with open("src/tools/keys/certificates.json", "r") as f:
                certificates = json.load(f)
        except:
            raise ValueError("No certificates found")
        
        if username in certificates:
            del certificates[username]
            with open("src/tools/keys/certificates.json", "w") as f:
                json.dump(certificates, f)


        # Remove conversation file
        try:
            os.remove(f"src/tools/conversations/{username}.json")
        except:
            pass

        # Remove messagesbox file
        try:
            os.remove(f"src/tools/messagesbox/{username}.json")
        except:
            pass

    @staticmethod
    def users_list():
        """
        Lists all users
        :return: None
        """
        # Get keys from src/tools/keys/public.json and src/tools/keys/
        try:
            with open("src/tools/keys/public.json", "r") as f:
                public_keys = json.load(f)
        except:
            raise ValueError("No keys found")

        users = []
        for user in public_keys:
            users.append(user)

        return users