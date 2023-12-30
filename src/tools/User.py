from tools.Cipher import RSA
import json

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
        return f'User: {self.username}'

    def getPublicKey(self):
        return self.public_key

    def getPrivateKey(self):
        return self.private_key

    def getUsername(self):
        return self.username
    
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
        # Get keys from src/tools/keys/public.json and src/tools/keys/
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