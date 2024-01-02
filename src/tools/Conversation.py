from tools.KDF import KDF
import json

class Conversation:
    def __init__(self, me, other, chain_key, salt):
        self.me = me
        self.other = other
        self.chain_key = chain_key
        self.salt = salt
        self.messages = []
        self.kfd = KDF(self.chain_key, self.salt, 256)

        # Save the conversation in src/tools/conversations/{me}.json with the other conversations
        try:
            with open(f"src/tools/conversations/{me.username}.json", "r") as f:
                conversations = json.load(f)

                if not self.other in conversations[me.username]:
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

        

        


    

   