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

    def __init__(self, key):
        super().__init__(key)
        self.SBox = SerpentCipher.sBoxGen()

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

        # Split the plaintext into 128 bits blocks
        blocks = self.splitPlainTextToBlocks(plaintext)

        # Initial permutation
        ciphertext = bitarray.bitarray()
        for block in blocks:
            ciphertext.extend(self.blockInitialPermutation(block))
    
        # Block encryption
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

        # Block decryption
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
        keys = self.iterationKeysGen()

        # 32 rounds
        for i in range(32):
            block = self.encryptRound(block, keys[i], self.SBox[i])

        return block
    
    def blockDecryption(self, block):
        """
        Serpent block decryption
        :param block: 128 bits block
        :return: 128 bits block
        """

        keys = self.iterationKeysGen()

        # 32 rounds
        for i in range(31,-1,-1):
            block = self.decryptRound(block, keys[i], self.SBox[i])
    

        return block
        
    def encryptRound(self, block, key, _SBox):
        """
        Serpent round
        :param block: 128 bits block
        :param key: 32 bits key
        :return: 128 bits block
        """


        # XOR with the key
        block = block ^ key

        # Sbox
        for i in range(0, len(block), 4):
            current = block[i:i+4]
            result = bin(_SBox[int(current.to01(), 2)])
            result = result[2:].zfill(4)
            block[i:i+4] = bitarray.bitarray(result)
        

        # Linear transformation
        block = self.encryptLinearTransformation(block)

        return block
    
    def decryptRound(self, block, key, _SBox):
        """
        Serpent round
        :param block: 128 bits block
        :param key: 32 bits key
        :return: 128 bits block
        """
        

        # Linear transformation
        block = self.decryptLinearTransformation(block)

        # Sbox
        for i in range(0, len(block), 4):
            current = block[i:i+4]
            result = bin(_SBox.index(int(current.to01(), 2)))
            result = result[2:].zfill(4)
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
        X2 = X2 ^ X3 ^ ModularMath.bit_shift(X1, 7, direction="left", bit_size=32)
        X0 = X0 ^ X1 ^ X3
        X3 = ModularMath.circular_bit_shift(X3, 7, direction="right", bit_size=32)
        X1 = ModularMath.circular_bit_shift(X1, 1, direction="right", bit_size=32)
        X3 = X3 ^ X2 ^ ModularMath.bit_shift(X0, 3, direction="left", bit_size=32)
        X1 = X1 ^ X0 ^ X2
        X2 = ModularMath.circular_bit_shift(X2, 3, direction="right", bit_size=32)
        X0 = ModularMath.circular_bit_shift(X0, 13, direction="right", bit_size=32)

        blocks[0] = X0
        blocks[1] = X1
        blocks[2] = X2
        blocks[3] = X3

        result = bitarray.bitarray(blocks[0].to01() + blocks[1].to01() + blocks[2].to01() + blocks[3].to01())

        return result
    

    def iterationKeysGen(self):
        """
        Iteration keys generation
        :return: list of 128 bits keys
        """
        keys = []
        w = [_ for _ in range(132)]

        # Split the key into 32 bits blocks
        blocks = []
        for i in range(0, len(self.key), 32):
            blocks.append(self.key[i:i+32])

        omega = bitarray.bitarray("10011110001101110111100110111001")

        # w0 to w7
        for i in range(8):
            w[i] = blocks[i]

        # w8 to w131
        for i in range(8, 132):
            w[i] = bitarray.bitarray(w[i-8]) ^ bitarray.bitarray(w[i-5]) ^ bitarray.bitarray(w[i-3]) ^ bitarray.bitarray(w[i-1]) ^ omega ^ bitarray.bitarray(bin(i)[2:].zfill(32))
            w[i] = ModularMath.circular_bit_shift(w[i], 11, direction="left", bit_size=32)
            w[i] = w[i].to01()


        for i in range(32):
            keys.append(bitarray.bitarray(w[4*i] + w[4*i+1] + w[4*i+2] + w[4*i+3]))

        return keys
        
    

    @staticmethod
    def keyGen():
        """
        Key generation
        256 bits key
        """
        return ''.join([random.choice(["0","1"]) for i in range(256)])
    

    @staticmethod
    def sBoxGen():
        """
        SBox generation
        """
        SBox = [[] for _ in range(32)]
        _table = [i for i in range(16)]
        for i in range(32):
            random.shuffle(_table)
            SBox[i] = _table.copy()
            
        return SBox
    


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

        
        
        

    