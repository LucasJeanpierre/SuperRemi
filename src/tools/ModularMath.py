import random
import bitarray

class ModularMath:
    """
    Modular Math Class
    Static methods for modular math operations
    """

    @staticmethod
    def gcd(a, b):
        """
        Euclidean algorithm for finding the greatest common divisor
        :param a: first integer
        :param b: second integer
        :return: greatest common divisor of a and b
        """
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def mod_inverse(a, m):
        """
        Extended Euclidean algorithm for finding the modular inverse
        :param a: integer
        :param m: modulus
        :return: modular inverse of a mod m
        """
        if ModularMath.gcd(a, m) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % m
    
    @staticmethod
    def is_prime(n, k=10):
        """
        Miller-Rabin primality test
        :param n: integer to test
        :param k: number of iterations
        :return: True if n is prime, False otherwise
        """
        if n < 2:
            return False
        if n != 2 and n % 2 == 0:
            return False
        s = n - 1
        while s % 2 == 0:
            s //= 2
        for _ in range(k):
            a = random.randrange(n - 1) + 1
            temp = s
            mod = pow(a, temp, n)
            while temp != n - 1 and mod != 1 and mod != n - 1:
                mod = (mod * mod) % n
                temp *= 2
            if mod != n - 1 and temp % 2 == 0:
                return False
        return True

    @staticmethod
    def generate_prime_number(bits):
        """
        Generate a prime number with a given number of bits
        :param bits: number of bits
        :return: prime number
        """
        while True:
            n = random.randrange(2**(bits-1), 2**(bits))
            if ModularMath.is_prime(n):
                return n


    @staticmethod
    def bit_shift(block, shift, direction="left", bit_size=32):
        """
        Bit shift
        :param block: bitarray to shift
        :param shift: number of bits to shift
        :param bit_size: size of the bitarray
        :param direction: direction of the shift
        :return: shifted bitarray
        """
        # bitarray to binary
        block = int(block.to01(), 2)

        result = None
        match direction:
            case "left":
                shift = shift % bit_size
                result = block << shift

                # keep only the last bit_size bits
                result = result & ((1 << bit_size) - 1)
            case "right":
                shift = shift % bit_size
                result = block >> shift

                # keep only the last bit_size bits
                result = result & ((1 << bit_size) - 1)
            case _:
                raise ValueError("Invalid direction")
            
        # binary to bitarray
        result = bitarray.bitarray(bin(result)[2:])

        # padding
        if len(result) < bit_size:
            result = bitarray.bitarray("0" * (bit_size - len(result))) + result

        return result

    @staticmethod
    def circular_bit_shift(block, shift, direction="left", bit_size=32):
        """
        Circular bit shift
        :param block: bitarray to shift
        :param shift: number of bits to shift
        :param bit_size: size of the bitarray
        :param direction: direction of the shift
        :return: shifted bitarray
        """

        # bitarrat to binary 
        block = int(block.to01(), 2)

        match direction:
            case "left":
                shift = shift % bit_size
                result = (block << shift) | (block >> (bit_size - shift))
                result = result & ((1 << bit_size) - 1)
            case "right":
                shift = shift % bit_size
                result = (block >> shift) | (block << (bit_size - shift))
                result = result & ((1 << bit_size) - 1)
            case _:
                raise ValueError("Invalid direction")
            
        # binary to bitarray
        result = bitarray.bitarray(bin(result)[2:])

        # padding
        if len(result) < bit_size:
            result = bitarray.bitarray("0" * (bit_size - len(result))) + result

        return result
    

    @staticmethod
    def euler_totient(n):
        """
        Euleur Totient function
        :param n: integer
        :return: Euleur Totient of n
        """

        result = 1
        for i in range(2, n):
            if ModularMath.gcd(i, n) == 1:
                result += 1
        return result