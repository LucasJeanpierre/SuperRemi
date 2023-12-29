from tools.Cipher import *
from tools.Hash import *
import logging
import json


DEBUG = True

logo = [
"   _____                       _____                _ ",
"  / ____|                     |  __ \\              (_)",
" | (___  _   _ _ __   ___ _ __| |__) |___ _ __ ___  _ ",
"  \\___ \\| | | | '_ \\ / _ \\ '__|  _   / _ \\ '_ ` _ \\| |",
"  ____) | |_| | |_) |  __/ |  | | \\ \\  __/ | | | | | |",
" |_____/ \\__,_| .__/ \\___|_|  |_|  \\_\\___|_| |_| |_|_|",
"              | |                                     ",
"              |_|                                     ",]

Instructions = [
    "->1<- Chiffrer un message (asymétrique)",
    "->2<- Déchiffrer un message (asymétrique)",
    "->3<- Générer un couple de clés",
    "->4<- Signer un certificat",
    "->5<- Vérifier un certificat",
    "->6<- Enregistrer un document dans un coffre fort",
    "->7<- Envoyer un message (asychrone)",
    "->8<- Demander un preuvce de connaissance",
    "->9<- Utiliser un utilisateur",
    "->10<- Quitter",
]

if __name__ == "__main__":
    
    if not DEBUG:
        try:
            with open("src/tools/keys/public.json", "r") as f:
                public_keys = json.load(f)
            with open("src/tools/keys/private.json", "r") as f:
                private_keys = json.load(f)
        except:
            public_keys = {}
            private_keys = {}
        
        current_user = None

        for line in logo:
            print(line)
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
        logging.info("Application started")

        while True:
            if current_user:
                print(f'User: {current_user}')

            for line in Instructions:
                print(line)
            choice = input("> ")

            match choice:
                case "1":
                    print("Chiffrer un message")

                case "2":
                    print("Déchiffrer un message")

                case "3":
                    username = input("Nom d'utilisateur: ")
                    if username in public_keys:
                        print("Utilisateur déjà existant")
                        continue
                    keys = RSA.keyGen()
                    print(keys[0])
                    user_public_key = {'user' : username, 'public_key' : keys[0]}
                    user_private_key = {'user' : username, 'private_key' : keys[1]}

                    public_keys[username] = keys[0]
                    private_keys[username] = keys[1]

                    with open("src/tools/keys/public.json", "w") as f:
                        json.dump(public_keys, f)
                    with open("src/tools/keys/private.json", "w") as f:
                        json.dump(private_keys, f)

                    logging.info("keys stored in files")

                case "4":
                    if current_user is None:
                        print("Veuillez choisir un utilisateur")
                        continue
                        
                    rsa = RSA(None, private_keys[current_user])
                    message = input("Message: ")
                    signature = rsa.sign(message)
                    print(signature)

                case "5":
                    user = input("Utilisateur à vérifier: ")
                    if user not in public_keys:
                        print("Utilisateur inconnu")
                        continue

                    rsa = RSA(public_keys[user], None)
                    message = input("Message: ")
                    signature = input("Signature: ")
                    if rsa.verify(message, signature):
                        print("Signature valide")
                    else:
                        print("Signature invalide")

                case "6":
                    print("Enregistrer un document dans un coffre fort")

                case "7":
                    print("Envoyer un message (asychrone)")

                case "8":
                    print("Demander un preuve de connaissance")

                case "9":
                    print("Liste des utilisateurs:")
                    for user in public_keys:
                        print(user)
                    username = input("Nom d'utilisateur: ")
                    if username not in public_keys:
                        print("Utilisateur inconnu")
                        continue
                    current_user = username

                case "10":
                    print("Quitter")
                    exit()

                case _:
                    print("Commande non reconnue")
    else:
        message = b'admin'
        hashed = sha256(message)
        print("SHA-256 Hash:", hashed)


