from tools.Cipher import *
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
    "->9<- Quitter",
]

if __name__ == "__main__":
    
    if not DEBUG:
        with open("keys.json", "r") as f:
            try:
                keys = json.load(f)
                public_key = keys["public_key"]
                private_key = keys["private_key"]
                secret_key = keys["secret_key"]
                logging.info("keys loaded from keys.json")
            except:
                public_key = None
                private_key = None
                secret_key = None

        print(public_key, private_key)


        for line in logo:
            print(line)
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
        logging.info("Application started")

        while True:
            for line in Instructions:
                print(line)
            choice = input("> ")

            match choice:
                case "1":
                    print("Chiffrer un message")
                    if public_key is None:
                        print("Veuillez générer une paire de clés")
                        continue
                    message = input("Message: ")
                    cipher = RSA(public_key, private_key)
                    encrypted_message = cipher.encrypt(message)
                    print("Message chiffré: ", encrypted_message)

                case "2":
                    print("Déchiffrer un message")
                    if private_key is None:
                        print("Veuillez générer une paire de clés")
                        continue
                    message = input("Message: ")
                    cipher = RSA(public_key, private_key)
                    decrypted_message = cipher.decrypt(message)
                    print("Message déchiffré: ", decrypted_message)

                case "3":
                    print("Générer un couple de clés")
                    keys = RSA.keyGen()
                    print("Clé publique: ", keys[0])
                    print("Clé privée: ", keys[1])
                    public_key = keys[0]
                    private_key = keys[1]

                    with open("keys.json", "w") as f:
                        json.dump({"public_key": public_key, "private_key": private_key, "secret_key": secret_key}, f)

                    logging.info("keys stored for the current session and in keys.json")

                case "4":
                    print("Signer un certificat")

                case "5":
                    print("Vérifier un certificat")

                case "6":
                    print("Enregistrer un document dans un coffre fort")

                case "7":
                    print("Envoyer un message (asychrone)")

                case "8":
                    print("Demander un preuve de connaissance")

                case "9":
                    print("Quitter")
                    exit()

                case _:
                    print("Commande non reconnue")
    else:
        secret_key = SerpentCipher.keyGen()
        Serpent = SerpentCipher(secret_key)
        message = "Hello World!"
        print("message: ", message)
        encrypted_message = Serpent.encrypt(message)
        print("encrypted message: ", encrypted_message)