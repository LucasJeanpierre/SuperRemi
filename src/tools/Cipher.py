import bitarray
from tools.ModularMath import ModularMath
import logging
import libnum
import random


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

    SBox = [
        [2, 12, 10, 4, 9, 14, 3, 11, 13, 5, 15, 6, 1, 0, 8, 7],
        [9, 4, 10, 0, 8, 2, 14, 12, 5, 6, 15, 11, 1, 13, 7, 3],
        [5, 10, 1, 15, 8, 2, 9, 7, 14, 6, 3, 4, 0, 11, 12, 13],
        [0, 9, 7, 13, 3, 1, 12, 4, 2, 8, 5, 6, 10, 15, 11, 14],
        [15, 14, 10, 4, 5, 9, 1, 12, 0, 2, 3, 11, 7, 6, 8, 13],
        [11, 2, 1, 0, 14, 7, 9, 15, 3, 12, 4, 10, 8, 13, 6, 5],
        [14, 6, 4, 1, 0, 7, 10, 2, 9, 12, 8, 11, 5, 3, 15, 13],
        [9, 12, 14, 8, 5, 10, 1, 13, 0, 2, 6, 7, 3, 11, 15, 4],
        [4, 0, 8, 13, 14, 5, 10, 1, 2, 7, 11, 12, 3, 9, 6, 15],
        [10, 13, 5, 14, 15, 4, 8, 0, 2, 3, 12, 7, 9, 1, 11, 6],
        [6, 11, 15, 13, 8, 2, 14, 12, 1, 5, 7, 10, 3, 4, 9, 0],
        [2, 5, 11, 13, 6, 3, 12, 0, 9, 10, 1, 7, 14, 8, 15, 4],
        [6, 10, 11, 0, 7, 1, 14, 8, 13, 9, 2, 15, 5, 12, 3, 4],
        [11, 10, 9, 2, 3, 5, 12, 14, 8, 4, 7, 15, 6, 13, 0, 1],
        [14, 6, 2, 5, 12, 4, 15, 1, 10, 8, 7, 0, 11, 3, 9, 13],
        [12, 14, 3, 10, 5, 8, 7, 13, 1, 0, 11, 4, 6, 2, 15, 9],
        [10, 9, 1, 6, 8, 14, 15, 5, 7, 12, 2, 3, 4, 0, 11, 13],
        [15, 4, 3, 2, 5, 10, 0, 14, 12, 7, 8, 1, 6, 9, 11, 13],
        [15, 8, 14, 5, 9, 10, 11, 13, 7, 4, 3, 12, 1, 6, 2, 0],
        [10, 5, 8, 6, 4, 14, 7, 2, 9, 13, 15, 3, 11, 0, 1, 12],
        [12, 7, 6, 13, 1, 2, 5, 10, 9, 0, 11, 14, 8, 4, 15, 3],
        [6, 3, 11, 13, 8, 5, 4, 10, 9, 12, 15, 2, 14, 7, 0, 1],
        [11, 4, 14, 5, 8, 0, 3, 10, 9, 12, 2, 7, 6, 1, 13, 15],
        [4, 3, 9, 11, 5, 8, 10, 12, 13, 7, 2, 15, 1, 6, 0, 14],
        [10, 11, 5, 1, 7, 3, 14, 15, 6, 4, 2, 9, 8, 0, 12, 13],
        [4, 11, 14, 9, 15, 1, 13, 2, 8, 10, 3, 7, 12, 0, 6, 5],
        [5, 1, 13, 7, 12, 9, 3, 10, 0, 15, 4, 11, 14, 6, 8, 2],
        [8, 2, 14, 9, 5, 4, 0, 12, 3, 7, 10, 11, 6, 15, 13, 1],
        [1, 11, 12, 2, 4, 6, 15, 10, 9, 7, 3, 8, 13, 5, 0, 14],
        [10, 13, 2, 8, 6, 4, 14, 0, 3, 9, 15, 7, 12, 11, 1, 5],
        [13, 14, 15, 4, 2, 5, 9, 12, 0, 7, 10, 3, 8, 11, 1, 6],
        [3, 8, 11, 7, 5, 13, 2, 12, 4, 9, 15, 1, 6, 10, 0, 14],
    ]

    def encrypt(self, plaintext):
        """
        Serpent encryption
        :param plaintext: plaintext
        :return ciphertext: str
        """

        # Split the plaintext into 128 bits blocks
        blocks = self.splitPlainTextToBlocks(plaintext)

        # Initial permutation
        ciphertext = bitarray.bitarray()
        for block in blocks:
            ciphertext.extend(self.blockInitialPermutation(block))
    
        # Sbox
        for i in range(0, len(ciphertext), 128):
            block = ciphertext[i:i+128]
            ciphertext[i:i+128] = self.blockEncryption(block)

        return ciphertext.to01()


    def decrypt(self, ciphertext):
        """
        Serpent decryption
        :param ciphertext: ciphertext
        :return plaintext: str
        """

        blocks = self.splitCipherTextToBlocks(ciphertext)
        plaintext = bitarray.bitarray()

        # Sbox
        for block in blocks:
            plaintext.extend(self.blockDecryption(block))
        
        # Final permutation
        for i in range(0, len(plaintext), 128):
            block = plaintext[i:i+128]
            plaintext[i:i+128] = self.blockFinalPermutation(block)

        # bitarray to str
        plaintext = plaintext.tobytes().decode("utf-8").replace("\x00", "")

        return plaintext
        

    

    def blockEncryption(self, block):
        """
        Serpent block encryption
        :param block: 128 bits block
        :return: 128 bits block
        """
        keys = [bitarray.bitarray(self.key) for i in range(32)]

        # 32 rounds
        for i in range(32):
            block = self.encryptRound(block, keys[i])
        return block
    
    def blockDecryption(self, block):
        """
        Serpent block decryption
        :param block: 128 bits block
        :return: 128 bits block
        """

        keys = [bitarray.bitarray(self.key) for i in range(32)]

        # 32 rounds
        for i in range(31,-1,-1):
            block = self.decryptRound(block, keys[i])

        return block
        
    def encryptRound(self, block, key):
        """
        Serpent round
        :param block: 128 bits block
        :param key: 32 bits key
        :return: 128 bits block
        """
        # Temporary
        # Force key size to 128 bits
        key = key[:128]

        # XOR with the key
        block = block ^ key

        # Sbox
        for i in range(0, len(block), 4):
            result = bin(int(block[i:i+4].to01(), 2))[2:].zfill(4)
            block[i:i+4] = bitarray.bitarray(result)

        # Linear transformation
        block = self.encryptLinearTransformation(block)

        return block
    
    def decryptRound(self, block, key):
        """
        Serpent round
        :param block: 128 bits block
        :param key: 32 bits key
        :return: 128 bits block
        """
        # Temporary
        # Force key size to 128 bits
        key = key[:128]

        # Linear transformation
        block = self.decryptLinearTransformation(block)

        # Sbox
        for i in range(0, len(block), 4):
            result = bin(int(block[i:i+4].to01(), 2))[2:].zfill(4)
            block[i:i+4] = bitarray.bitarray(result)

        # XOR with the key
        block = block ^ key

        return block
    

    def encryptLinearTransformation(self, block):
        """
        Serpent linear transformation
        :param block: 128 bits block
        :return: 128 bits block
        """
        
        # Split the block into 4 32 bits blocks
        blocks = []
        for i in range(0, len(block), 32):
            blocks.append(block[i:i+32])

        X0 = blocks[0]
        X1 = blocks[1]
        X2 = blocks[2]
        X3 = blocks[3]

        X0 = ModularMath.circular_bit_shift(X0, 13, direction="left", bit_size=32)
        X2 = ModularMath.circular_bit_shift(X2, 3, direction="left", bit_size=32)
        X1 = X1 ^ X0 ^ X2
        X3 = X3 ^ X2 ^ ModularMath.bit_shift(X0, 3, direction="left", bit_size=32)
        X1 = ModularMath.circular_bit_shift(X1, 1, direction="left", bit_size=32)
        X3 = ModularMath.circular_bit_shift(X3, 7, direction="left", bit_size=32)
        X0 = X0 ^ X1 ^ X3
        X2 = X2 ^ X3 ^ ModularMath.bit_shift(X1, 7, direction="left", bit_size=32)
        X0 = ModularMath.circular_bit_shift(X0, 5, direction="left", bit_size=32)
        X2 = ModularMath.circular_bit_shift(X2, 22, direction="left", bit_size=32)

        blocks[0] = X0
        blocks[1] = X1
        blocks[2] = X2
        blocks[3] = X3

        result = bitarray.bitarray(blocks[0].to01() + blocks[1].to01() + blocks[2].to01() + blocks[3].to01())
        
        return result
    
    def decryptLinearTransformation(self, block):
        """
        Serpent linear transformation
        :param block: 128 bits block
        :return: 128 bits block
        """
        
        # Split the block into 4 32 bits blocks
        blocks = []
        for i in range(0, len(block), 32):
            blocks.append(block[i:i+32])

        X0 = blocks[0]
        X1 = blocks[1]
        X2 = blocks[2]
        X3 = blocks[3]

        X2 = ModularMath.circular_bit_shift(X2, 22, direction="right", bit_size=32)
        X0 = ModularMath.circular_bit_shift(X0, 5, direction="right", bit_size=32)



        return block
        
    

    @staticmethod
    def keyGen():
        """
        Key generation
        256 bits key
        """
        return ''.join([random.choice(["0","1"]) for i in range(256)])


    @staticmethod
    def splitPlainTextToBlocks(plaintext):
        """
        Split the plaintext into 128 bits blocks
        :param plaintext: plaintext
        :return: list of bitarray of 128 bits blocks
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
        :return: list of bitarray of 128 bits blocks
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

        
        
        

    