import unittest
from tools.ModularMath import ModularMath
from tools.Cipher import RSA, SerpentCipher

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


class TestRSA(unittest.TestCase):
    
    def test_rsa(self):
        public_key, private_key = RSA.keyGen()
        message = "Hello World!"
        cipher = RSA(public_key, private_key)
        encrypted_message = cipher.encrypt(message)
        decrypted_message = cipher.decrypt(encrypted_message)
        self.assertEqual(message, decrypted_message)
        


class TestSerpent(unittest.TestCase):
    
    def test_serpent(self):
        Serpent = SerpentCipher("bonsoir")
        message = "Hello World!"
        encrypted_message = Serpent.encrypt(message)
        decrypted_message = Serpent.decrypt(encrypted_message)
        self.assertEqual(message, decrypted_message)

if __name__ == "__main__":
    unittest.main()
