from tools.Cipher import *
from tools.Hash import *
from tools.CertificateAuthority import *
from tools.User import *
from tools.KDF import *
from tools.ModularMath import *
import logging
import json


DEBUG = False
CUSTOM = True

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
    "->1<- Chiffrer/Déchiffrer un message",
    "->2<- Générer un couple de clés",
    "->3<- Signer un certificat",
    "->4<- Vérifier un certificat",
    "->5<- Enregistrer un document dans un coffre fort",
    "->6<- Envoyer un message (asychrone)",
    "->7<- Demander un preuve de connaissance",
    "->8<- Quitter",
]

Custom_Instructions = [
    "->1<- Create user",
    "->2<- Delete user",
    "->3<- Select user",
    "->4<- Send message (Asymetric)",
    "->5<- Read message (Asymetric)",
    "->6<- Create certificate",
    "->7<- Verify certificate",
    "->8<- Start Conversation (Symetric)",
    "->9<- Send message (Symetric)",
    "->10<- Read message (Symetric)",
    "->11<- Proof of knowledge",
    "->12<- Exit",
]


def chooseUser():
    public_keys = User.users_list()
    print("Liste des utilisateurs:")
    for user in public_keys:
        print(user)
    username = input("Nom d'utilisateur: ")
    if username not in public_keys:
        print("Utilisateur inconnu")
        user = None
    user = username
    return user


def instructionHandler():
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


if __name__ == "__main__":
    if CUSTOM == False:
        instructionHandler()
    elif DEBUG == True:

        # Peggy (prover)
        AliceKeys = RSA.keyGen()

        N = AliceKeys[0][0]
        e = AliceKeys[0][1]


        print(f"N : {N}")
        print(f"e : {e}")

        x = AliceKeys[1][1]
        X = pow(x, e, N)

        x = AliceKeys[1][1]

        print(f"x : {x}")

        print(f"X : {X}")

        y = random.randrange(pow(2,254), pow(2,255))

        while (ModularMath.gcd(y,N)) != 1:
            y = random.randrange(pow(2,254), pow(2,255))



        print(f"y : {y}")

        Y = pow(y, e, N)

        print(f"Y : {Y}")

        # Victor (verifier)

        c = random.randrange(pow(2,254), pow(2,255))

        # Peggy (prover)

        z = (y * pow(x, c, N)) % N

        # Victor (verifier)

        val1 = pow(z, e, N)
        val2 = (Y * pow(X, c, N)) % N

        print(f"val1 : {val1}")
        print(f"val2 : {val2}")
        print(f"val1 == val2 : {val1 == val2}")






    else:
        current_user = None

        for line in logo:
            print(line)


        while True:

            print("-"*25)

            if current_user:
                print(f'User: {current_user}')
            
            for line in Custom_Instructions:
                print(line)
            choice = input("> ")

            match choice:
                case "1":
                    print("Create user")
                    username = input("Username > ")
                    try:
                        User.create_user(username)
                    except ValueError as e:
                        print(e)
                        continue

                case "2":
                    print("Delete user")
                    [print(user) for user in User.users_list()]
                    username = input("Username > ")
                    try:
                        User.delete_user(username)
                    except ValueError as e:
                        print(e)
                        continue

                case "3":
                    print("Select user")
                    print("List :")
                    [print(user) for user in User.users_list()]
                    username = input("> ")
                    if username not in User.users_list():
                        print("Unknown user")
                        continue
                    current_user = User(username)

                case "4":
                    print("Send message")
                    if current_user is None:
                        print("Please select a user")
                        continue
                        
                    print("List :")
                    [print(user) for user in User.users_list()]
                    username = input("User > ")

                    if username not in User.users_list():
                        print("Unknown user")
                        continue

                    message = input("Message > ")

                    current_user.send_message_asymetric(message, username)
                    

                case "5":
                    print("Read message")
                    if current_user is None:
                        print("Please select a user")
                        continue

                    messages = current_user.get_messages_asymetric()
                    print("Messages :")
                    for id, message in messages.items():
                        print(f"id : {id}")
                        print(f"sender : {message['sender']}")
                        print(f"time : {message['time']}")
                        print(f"message : {message['message']}")
                        print("")

                case "6":
                    print("Create certificate")
                    if current_user is None:
                        print("Please select a user")
                        continue
                        
                    certificateAuthority = CertificateAuthority.getAuthority()
                    certificate = certificateAuthority.create_certificate(current_user.getPublicKey(), current_user.getUsername(), current_user.getProof())
                    print(f"Certificat de {current_user}: {certificate}")

                case "7":
                    print("Verify certificate")
                    print("List :")
                    [print(user) for user in User.users_list()]
                    username = input("> ")

                    if username not in User.users_list():
                        print("Unknown user")
                        continue

                    user = User(username)
                    certificate = user.getCertificate()

                    certificateAuthority = CertificateAuthority.getAuthority()
                    validity = certificateAuthority.verify_certificate(certificate)

                    print(f"Certificat de {user.getUsername()} valide: {validity}")

                case "8":
                    print("Start conversation")

                    if current_user is None:
                        print("Please select a user")
                        continue


                    print("List :")
                    [print(user) for user in User.users_list()]
                    username = input("> ")

                    if username not in User.users_list():
                        print("Unknown user")
                        continue

                    other = User(username)
                    chain_key = KDF.generate_chain_key()
                    salt = KDF.generate_salt()

                    logging.info(f"chain_key : {chain_key}")
                    logging.info(f"salt : {salt}")

                    Conversation.create_conversation(current_user, other, chain_key, salt)


                case "9":
                    print("Send message")
                    if current_user is None:
                        print("Please select a user")
                        continue

                    print("List :")
                    [print(user) for user in User.users_list()]
                    username = input("> ")

                    if username not in User.users_list():
                        print("Unknown user")
                        continue

                    message = input("Message > ")

                    other = User(username)
                    conversation = Conversation(current_user, other)
                    current_user.setConversation(conversation)
                    current_user.send_message_conversation(message)


                case "10":
                    print("Read message")
                    if current_user is None:
                        print("Please select a user")
                        continue

                    print("List :")
                    [print(user) for user in User.users_list()]
                    username = input("> ")

                    other = User(username)

                    conversation = Conversation(current_user, other)
                    current_user.setConversation(conversation)

                    messages = current_user.get_messages_conversation()
                    print("Messages :")
                    for message in messages:
                        print(f"id : {message['id']}")
                        print(f"sender : {message['sender']}")
                        print(f"time : {message['time']}")
                        print(f"message : {message['message']}")
                        print("")

                case "11":
                    print("Proof of knowledge")
                    if current_user is None:
                        print("Please select a user")
                        continue

                    print("List :")
                    [print(user) for user in User.users_list()]
                    username = input("> ")

                    if username not in User.users_list():
                        print("Unknown user")
                        continue

                    other = User(username)

                    print(f'Validity : {current_user.ask_for_proof_of_knowledge(other.getUsername())}')



                case "12":
                    print("Exit")
                    exit()

   
    

