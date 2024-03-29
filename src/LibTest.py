import unittest
import bitarray
from tools.ModularMath import ModularMath
from tools.Cipher import RSA, SerpentCipher
from tools.Hash import sha256, hmac_sha256
from tools.CertificateAuthority import CertificateAuthority
from tools.User import User
from tools.KDF import KDF
from tools.Conversation import Conversation
from tools.BlockChain import Blockchain
import json

class TestGCD(unittest.TestCase):

    def test_gcd_1(self):
        self.assertEqual(ModularMath.gcd(3, 5), 1)

    def test_gcd_2(self):
        self.assertEqual(ModularMath.gcd(3, 6), 3)

    def test_gcd_3(self):
        self.assertEqual(ModularMath.gcd(3, 9), 3)

    def test_gcd_4(self):
        self.assertEqual(ModularMath.gcd(3, 15), 3)

    def test_gcd_5(self):
        self.assertEqual(ModularMath.gcd(221, 782), 17)


class TestEulerTotient(unittest.TestCase):
        
    def test_euler_totient_1(self):
        self.assertEqual(ModularMath.euler_totient(7), 6)

    def test_euler_totient_2(self):
        self.assertEqual(ModularMath.euler_totient(10), 4)

    def test_euler_totient_3(self):
        self.assertEqual(ModularMath.euler_totient(123456), 41088)
        


class TestModInverse(unittest.TestCase):
    
    def test_mod_inverse_1(self):
        self.assertEqual(ModularMath.mod_inverse(3, 7), 5)

    def test_mod_inverse_2(self):
        self.assertEqual(ModularMath.mod_inverse(3, 8), 3)

    def test_mod_inverse_3(self):
        self.assertEqual(ModularMath.mod_inverse(3, 9), None)

    def test_mod_inverse_4(self):
        self.assertEqual(ModularMath.mod_inverse(15, 782), 365)

    def test_mod_inverse_5(self):
        self.assertEqual(ModularMath.mod_inverse(221, 782), None)


class TestIsPrime(unittest.TestCase):
        
    def test_is_prime_1(self):
        self.assertEqual(ModularMath.is_prime(1), False)

    def test_is_prime_2(self):
        self.assertEqual(ModularMath.is_prime(2), True)

    def test_is_prime_3(self):
        self.assertEqual(ModularMath.is_prime(6173), True)

    def test_is_prime_4(self):
        self.assertEqual(ModularMath.is_prime(265252859812191058636308479999999), True)

    def test_is_prime_5(self):
                self.assertEqual(ModularMath.is_prime(13216587986546542), False)

class TestCirularShift(unittest.TestCase):
        
    def test_circular_shift_1(self):
        self.assertEqual(ModularMath.circular_bit_shift(bitarray.bitarray("1001"), 1, direction="left", bit_size=4), bitarray.bitarray("0011"))

    def test_circular_shift_2(self):
        self.assertEqual(ModularMath.circular_bit_shift(bitarray.bitarray("1001"), 1, direction="right", bit_size=4), bitarray.bitarray("1100"))

    def test_circular_shift_3(self):
        self.assertEqual(ModularMath.circular_bit_shift(bitarray.bitarray("00000000000000001111111111111111"), 2, direction="left", bit_size=32), bitarray.bitarray("00000000000000111111111111111100"))



class TestBitShift(unittest.TestCase):
     
    def test_bit_shift_1(self):
        self.assertEqual(ModularMath.bit_shift(bitarray.bitarray("1001"), 1, direction="left", bit_size=4), bitarray.bitarray("0010"))

    def test_bit_shift_2(self):
        self.assertEqual(ModularMath.bit_shift(bitarray.bitarray("1001"), 1, direction="right", bit_size=4), bitarray.bitarray("0100"))

    def test_bit_shift_3(self):
        self.assertEqual(ModularMath.bit_shift(bitarray.bitarray("00000000000000001111111111111111"), 2, direction="left", bit_size=32), bitarray.bitarray("00000000000000111111111111111100"))

     
     

class TestRSA(unittest.TestCase):

    def test_rsa_encryption(self):
        public_key, private_key = RSA.keyGen()
        cipher = RSA(public_key, private_key)
        message = "Hello World!"
        encrypted_message = cipher.encrypt(message)
        decrypted_message = cipher.decrypt(encrypted_message)
        self.assertEqual(message, decrypted_message)

    def test_rsa_encryption_2(self):
        public_key, private_key = RSA.keyGen()
        cipher = RSA(public_key, private_key)
        message = "Hello World!"
        encrypted_message = cipher.encrypt(message, key="Private")
        decrypted_message = cipher.decrypt(encrypted_message, key="Public")
        self.assertEqual(message, decrypted_message)

    def test_rsa_signing_correct(self):
        public_key, private_key = RSA.keyGen()
        cipher = RSA(public_key, private_key)
        message = "Hello World!"
        signature = cipher.sign(message)
        self.assertEqual(cipher.verify(message, signature), True)

    def test_rsa_signing_incorrect(self):
        public_key, private_key = RSA.keyGen()
        cipher = RSA(public_key, private_key)
        message = "Hello World!"
        signature = cipher.sign(message)
        public_key2, private_key2 = RSA.keyGen()
        cipher2 = RSA(public_key2, private_key2)
        self.assertEqual(cipher2.verify("Hello World", signature), False)
        


class TestSerpent(unittest.TestCase):

    def test_serpent_encryption(self):
        key = SerpentCipher.keyGen()
        Serpent = SerpentCipher(key)
        message = "Hello World!"
        encrypted_message = Serpent.encrypt(message)
        decrypted_message = Serpent.decrypt(encrypted_message)
        self.assertEqual(message, decrypted_message)


class TestHash(unittest.TestCase):

    def test_sha256_1(self):
        self.assertEqual(sha256(b"admin"), "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918")

    def test_sha256_1(self):
        self.assertEqual(sha256(b"gs15"), "d56a96741074dbb41a112252750dedaab23dcb0840e23c1eaebb902472f9b3d8")

    def test_hmac_sha256_1(self):
        self.assertEqual(hmac_sha256(b"admin", b"admin"), "f429ec54f354b72bed77a5c0afedecb91f347f479a09f74f4107592764b56d1c")

    def test_hmac_sha256_1(self):
        self.assertEqual(hmac_sha256(b"admin", b"gs15"), "0af840f4ce055536ff9919d1016f880c9112f356d46a69c5f2ca4e92bfbe7f2c")

class TestCertificateAuthority(unittest.TestCase):

    def test_certificate_authority(self):
        with open("src/tools/keys/authority.json", "r") as f:
            authority_keys = json.load(f)

        keys = RSA.keyGen()
        User.create_user("CertificateTest", keys=keys)
        
        user = User("CertificateTest")


        Authority = CertificateAuthority(authority_keys['public'], authority_keys['private'])

        keys = RSA.keyGen()
        WrongAuthority = CertificateAuthority(keys[0], keys[1])

        CompanyCertificate = Authority.create_certificate(user.getPublicKey(), user.username, user.generateProof())
        WrongCompanyCertificate = WrongAuthority.create_certificate(user.getPublicKey(), user.username, user.generateProof())

        self.assertEqual(Authority.verify_certificate(CompanyCertificate), True)
        self.assertEqual(Authority.verify_certificate(WrongCompanyCertificate), False)

        User.delete_user("CertificateTest")


class TestUser(unittest.TestCase):

    def test_user(self):
        username = "test"
        keys = RSA.keyGen()
        User.create_user(username,keys=keys)
        user = User(username)
        self.assertEqual(keys[0],user.getPublicKey())
        User.delete_user(username)
        self.assertRaises(ValueError, User, username)


class TestKDF(unittest.TestCase):

    def test_kdf(self):
        KDF_Alice = KDF("chain_key", "salt", 256)
        KDF_Bob = KDF("chain_key", "salt", 256)

        for _ in range(10):
            serpentAlice = SerpentCipher(KDF_Alice.derive())
            serpentBob = SerpentCipher(KDF_Bob.derive())

            message = "Hello World!"
            encrypted_message = serpentAlice.encrypt(message)
            decrypted_message = serpentBob.decrypt(encrypted_message)

            self.assertEqual(message, decrypted_message)


class TestConversation(unittest.TestCase):
    
    def test_conversation(self):
        User.create_user("AliceTest")
        User.create_user("BobTest")
        Alice = User("AliceTest")
        Bob = User("BobTest")

        chain_key = "chain_key"
        salt = "salt"

        Conversation.create_conversation(Alice, Bob, chain_key, salt)
        alice_conversation = Conversation(Alice, Bob)
        Alice.setConversation(alice_conversation)
        Alice.send_message_conversation("Hello World!")

        bob_conversation = Conversation(Bob, Alice)
        Bob.setConversation(bob_conversation)

        self.assertEqual(Bob.get_messages_conversation()[0]['message'], "Hello World!")

        User.delete_user("AliceTest")
        User.delete_user("BobTest")


class TestProofOfKnowledge(unittest.TestCase):

    def test_proof_of_knowledge_valid(self):

        User.create_user("AliceTest")
        User.create_user("BobTest")

        Alice = User("AliceTest")
        Bob = User("BobTest")

        certificateAuthority = CertificateAuthority.getAuthority()
        certificateAuthority.create_certificate(Alice.getPublicKey(), Alice.getUsername(), Alice.generateProof())

        self.assertEqual(Bob.ask_for_proof_of_knowledge(Alice.getUsername()),True)

        User.delete_user("AliceTest")
        User.delete_user("BobTest")

    def test_proof_of_knowledge_invalid(self):

        User.create_user("AliceTest")
        User.create_user("BobTest")

        Alice = User("AliceTest")
        Bob = User("BobTest")

        certificateAuthority = CertificateAuthority.getAuthority()
        certificateAuthority.create_certificate(Alice.getPublicKey(), Alice.getUsername(), 15)

        self.assertEqual(Bob.ask_for_proof_of_knowledge(Alice.getUsername()),False)

        User.delete_user("AliceTest")
        User.delete_user("BobTest")


class TestDiffieHellman(unittest.TestCase):

    def test_diffie_hellman(self):
        User.create_user("AliceTest")
        User.create_user("BobTest")

        Alice = User("AliceTest")
        Bob = User("BobTest")

        Alice.diffie_hellman_init(Bob)

        self.assertEqual(Alice.diffie_hellman_key, Bob.diffie_hellman_key)

        User.delete_user("AliceTest")
        User.delete_user("BobTest")

class TestBlockChain(unittest.TestCase):

    def test_initblockchain(self):
        blockchain = Blockchain()
        blockchain.add_block("Alice", "Hello")

        self.assertEqual(blockchain.get_latest_block().data, "Hello")
        

if __name__ == "__main__":
    unittest.main()
