from tools.Cipher import *
from tools.Hash import *
from tools.CertificateAuthority import *
import logging
import json


DEBUG = False

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


def chooseUser():
    print("Liste des utilisateurs:")
    for user in public_keys:
        print(user)
    username = input("Nom d'utilisateur: ")
    if username not in public_keys:
        print("Utilisateur inconnu")
        user = None
    user = username
    return user

if __name__ == "__main__":
    
    if not DEBUG:
        # Get keys from src/tools/keys/public.json and src/tools/keys/private.json
        try:
            with open("src/tools/keys/public.json", "r") as f:
                public_keys = json.load(f)
            with open("src/tools/keys/private.json", "r") as f:
                private_keys = json.load(f)
        except:
            public_keys = {}
            private_keys = {}
        
        current_user = None

        # Get Certificate Authority from src/tools/keys/authority.json
        with open("src/tools/keys/authority.json", "r") as f:
            authority_keys = json.load(f)
        certificateAuthority = CertificateAuthority(authority_keys['public'], authority_keys['private'])

        # Print logo
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
                        
                    certificate = certificateAuthority.create_certificate(public_keys[current_user], current_user)
                    print(f"Certificat de {current_user}: {certificate}")


                case "5":
                    user = chooseUser()
                    if user not in public_keys:
                        print("Utilisateur inconnu")
                        continue

                    # Get certificate from src/tools/keys/certificates.json
                    with open("src/tools/keys/certificates.json", "r") as f:
                        certificates = json.load(f)
                    certificate = certificates[user]

                    validity = certificateAuthority.verify_certificate(certificate)

                    print(f"Certificat de {user} valide: {validity}")

                case "6":
                    print("Enregistrer un document dans un coffre fort")

                case "7":
                    print("Envoyer un message (asychrone)")

                case "8":
                    print("Demander un preuve de connaissance")

                case "9":
                    current_user = chooseUser()

                case "10":
                    print("Quitter")
                    exit()

                case _:
                    print("Commande non reconnue")
    else:
        # Get keys from src/tools/keys/authority.json
        with open("src/tools/keys/authority.json", "r") as f:
            authority_keys = json.load(f)

        Authority = CertificateAuthority(authority_keys['public'], authority_keys['private'])

        Company = RSA.keyGen()

        # Create a certificate for the company
        CompanyCertificate = Authority.create_certificate(Company[0], "Alice")

    

