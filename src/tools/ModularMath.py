import random

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

