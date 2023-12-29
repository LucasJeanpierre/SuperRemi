import libnum
from tools.Hash import sha256
import json

class CertificateAuthority:
    def __init__(self, public_key, private_key):
        # Initialize the CA with its own key pair
        self.public_key = public_key
        self.private_key = private_key

    def create_certificate(self, entity_public_key, entity_name):
        # Create a certificate for the entity
        certificate_data = f"{entity_name}:{entity_public_key[0]}:{entity_public_key[1]}"

        # Hash the certificate data
        hashed_data = sha256(certificate_data.encode())

        # Sign the hashed data using the CA's private key
        signature = pow(libnum.s2n(hashed_data), self.private_key[1], self.private_key[0])

        # Return the certificate
        certificate = {
            'entity_name': entity_name,
            'entity_public_key': entity_public_key,
            'signature': signature
        }

        # Save the certificate in src/tools/certificate.json with the other certificates
        try:
            with open("src/tools/keys/certificates.json", "r") as f:
                certificates = json.load(f)
        except:
            certificates = {}
        certificates[entity_name] = certificate
        with open("src/tools/keys/certificates.json", "w") as f:
            json.dump(certificates, f)

        return certificate

    def verify_certificate(self, certificate):
        # Extract information from the certificate
        entity_name = certificate['entity_name']
        entity_public_key = certificate['entity_public_key']
        signature = certificate['signature']

        # Recreate the certificate data
        certificate_data = f"{entity_name}:{entity_public_key[0]}:{entity_public_key[1]}"

        # Hash the certificate data
        hashed_data = sha256(certificate_data.encode())

        # Verify the signature using the CA's public key
        is_valid_signature = libnum.n2s(pow(signature, self.public_key[1], self.public_key[0])) == hashed_data.encode()

        return is_valid_signature
