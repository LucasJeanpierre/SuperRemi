import bitarray
from tools.ModularMath import ModularMath
import logging
import libnum


class Cipher():

    """
    Abstract Cipher class
    """

    def encrypt(self, plaintext):
        pass

    def decrypt(self, ciphertext):
        pass

    @staticmethod
    def keyGen():
        pass


class SymmetricCipher(Cipher):

    """
    Symmetric Cipher class
    """

    def __init__(self, key):
        self.key = key


class AsymmetricCipher(Cipher):
    
    """
    Asymmetric Cipher class
    """

    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

        


class SerpentCipher(SymmetricCipher):

    """
    Serpent Cipher class
    Using 256 bits key
    """

    IPTable = [
        0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99, 4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103, 8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107, 12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111, 16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115, 20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119, 24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123, 28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127
    ]

    FPTable = [
        0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126, 3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63, 67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127
    ]

    def encrypt(self, plaintext):
        """
        Serpent encryption
        :param plaintext: plaintext
        :return ciphertext: str
        """

        blocks = self.splitPlainTextToBlocks(plaintext)
        ciphertext = bitarray.bitarray()
        for block in blocks: 
            ciphertext.extend(self.blockInitialPermutation(block))
        return ciphertext.to01()


    def decrypt(self, ciphertext):
        """
        Serpent decryption
        :param ciphertext: ciphertext
        :return plaintext: str
        """
        
        blocks = self.splitCipherTextToBlocks(ciphertext)
        plaintext = bitarray.bitarray()
        for block in blocks:
            plaintext.extend(self.blockFinalPermutation(block))
        return plaintext.tobytes().decode("utf-8").rstrip('\x00')



    @staticmethod
    def splitPlainTextToBlocks(plaintext):
        """
        Split the plaintext into 128 bits blocks
        :param plaintext: plaintext
        :return: bitarray of 128 bits blocks
        """

        # Turn the plaintext into a bitarray
        ba = bitarray.bitarray()
        ba.frombytes(plaintext.encode("utf-8"))

        # Add padding if necessary
        if len(ba) % 128 != 0:
            ba.extend(bitarray.bitarray("0" * (128 - len(ba) % 128)))

        # Split the plaintext into 128 bits blocks
        blocks = []
        for i in range(0, len(ba), 128):
            blocks.append(ba[i:i+128])

        return blocks
    
    @staticmethod
    def splitCipherTextToBlocks(ciphertext):
        """
        Split the ciphertext into 128 bits blocks
        :param ciphertext: ciphertext
        :return: bitarray of 128 bits blocks
        """

        # Turn the ciphertext into a bitarray
        ba = bitarray.bitarray(ciphertext)

        # Split the ciphertext into 128 bits blocks
        blocks = []
        for i in range(0, len(ba), 128):
            blocks.append(ba[i:i+128])

        return blocks


    @staticmethod
    def blockInitialPermutation(block):
        """
        Initial permutation of the block
        :param block: 128 bits block
        :return: 128 bits block
        """
        return bitarray.bitarray([block[i] for i in SerpentCipher.IPTable])
    
    @staticmethod
    def blockFinalPermutation(block):
        """
        Final permutation of the block
        :param block: 128 bits block
        :return: 128 bits block
        """
        return bitarray.bitarray([block[i] for i in SerpentCipher.FPTable])
    



class RSA(AsymmetricCipher):

    """
    RSA Cipher class
    """

    @staticmethod
    def keyGen():
        """
        Key generation
        2048 digits numbers
        """
        p = ModularMath.generate_prime_number(1024)
        q = ModularMath.generate_prime_number(1024)
        logging.debug("p = %d", p)
        logging.debug("q = %d", q)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = ModularMath.mod_inverse(e, phi)
        return (n, e), (n, d)

    def encrypt(self, plaintext):
        """
        RSA encryption
        """
        plaintext = libnum.s2n(plaintext)
        ciphertext = pow(plaintext, self.public_key[1], self.public_key[0])
        return ciphertext

    def decrypt(self, ciphertext):
        """
        RSA decryption
        """
        ciphertext = int(ciphertext)
        plaintext = pow(ciphertext, self.private_key[1], self.private_key[0])
        plaintext = str(libnum.n2s(plaintext))[2:-1]
        return plaintext

        
        
        

    