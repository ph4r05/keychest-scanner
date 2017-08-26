#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import random
from past.builtins import xrange


class CyclicTools(object):
    """
    Cyclic tools - generating cyclic multiplicative group for generating random walk.
    """

    def __init__(self, n=None, prime=None, generator=None):
        self.prime = prime
        self.prime_m1_fact = None
        self.generator = generator
        self.n = n

    def init(self, n=None):
        """
        Finds nearest prime and a random generator
        :param n:
        :return:
        """
        if n is not None:
            self.n = n

        if self.n is None:
            raise ValueError('n cannot be None')

        self.prime = CyclicTools.next_prime(self.n + 1)
        self.prime_m1_fact = list(set(CyclicTools.prime_factors(self.prime - 1)))
        self.generator = CyclicTools.find_generator(self.prime, self.prime_m1_fact)

    def iter(self):
        """
        Iterator
        :return:
        """
        g0 = self.generator
        g = self.generator
        for i in xrange(0, self.prime - 1):
            g = (g * g0) % self.prime
            if g > self.n:
                continue
            yield g

    @staticmethod
    def next_prime(inp, nice=False):
        """
        Finds next prime equal or greater than inp
        :param inp:
        :param nice: sophie germain?
        :return:
        """
        ads = 0 if inp & 1 else 1
        while True:
            if CyclicTools.prime3(inp + ads):
                if not nice or CyclicTools.prime3((inp + ads) / 2):
                    return inp + ads
            ads += 2

    @staticmethod
    def prime3(a):
        """
        Simple trial division prime detection
        :param a:
        :return:
        """
        if a < 2:
            return False
        if a == 2 or a == 3:
            return True  # manually test 2 and 3
        if a % 2 == 0 or a % 3 == 0:
            return False  # exclude multiples of 2 and 3

        max_divisor = int(math.ceil(a ** 0.5))
        d, i = 5, 2
        while d <= max_divisor:
            if a % d == 0:
                return False
            d += i
            i = 6 - i  # this modifies 2 into 4 and vice versa

        return True

    @staticmethod
    def prime_factors(n):
        """
        Simple trial division factorization
        :param n:
        :return:
        """
        num = []

        # add 2, 3 to list or prime factors and remove all even numbers(like sieve of ertosthenes)
        while n % 2 == 0:
            num.append(2)
            n /= 2

        while n % 3 == 0:
            num.append(3)
            n /= 3

        max_divisor = int(math.ceil(n ** 0.5))
        d, i = 5, 2
        while d <= max_divisor:
            while n % d == 0:
                num.append(d)
                n /= d

            d += i
            i = 6 - i  # this modifies 2 into 4 and vice versa

        # if no is > 2 i.e no is a prime number that is only divisible by itself add it
        if n > 2:
            num.append(n)

        return num

    @staticmethod
    def find_generator(p, fact):
        """
        4.80 Handbook of applied cryptography - finding generator of a cyclic group
        http://cacr.uwaterloo.ca/hac/about/chap4.pdf

        :param p: group order (prime pls)
        :param fact: ((p-1) / 2) prime factorization
        :return:
        """
        nps = [p / k for k in fact]
        while True:
            g = random.randint(2, p - 1)
            fail = False
            for np in nps:
                if pow(g, np, p) == 1:
                    fail = True
                    break
            if not fail:
                return g

    @staticmethod
    def generate(p, g):
        """
        Generate the whole cyclic multiplicative group with order and generator
        :param p: order
        :param g: generator
        :return:
        """
        g0 = g
        for i in xrange(0, p - 1):
            g = (g * g0) % p
            yield g

    @staticmethod
    def modular_sqrt(a, p):
        """ Find a quadratic residue (mod p) of 'a'. p
            must be an odd prime.

            Solve the congruence of the form:
                x^2 = a (mod p)
            And returns x. Note that p - x is also a root.

            0 is returned is no square root exists for
            these a and p.

            The Tonelli-Shanks algorithm is used (except
            for some simple cases in which the solution
            is known from an identity). This algorithm
            runs in polynomial time (unless the
            generalized Riemann hypothesis is false).
        """
        # Simple cases
        #
        if CyclicTools.legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return p
        elif p % 4 == 3:
            return pow(a, (p + 1) / 4, p)

        # Partition p-1 to s * 2^e for an odd s (i.e.
        # reduce all the powers of 2 from p-1)
        #
        s = p - 1
        e = 0
        while s % 2 == 0:
            s /= 2
            e += 1

        # Find some 'n' with a legendre symbol n|p = -1.
        # Shouldn't take long.
        #
        n = 2
        while CyclicTools.legendre_symbol(n, p) != -1:
            n += 1

        # Here be dragons!
        # Read the paper "Square roots from 1; 24, 51,
        # 10 to Dan Shanks" by Ezra Brown for more
        # information
        #

        # x is a guess of the square root that gets better
        # with each iteration.
        # b is the "fudge factor" - by how much we're off
        # with the guess. The invariant x^2 = ab (mod p)
        # is maintained throughout the loop.
        # g is used for successive powers of n to update
        # both a and b
        # r is the exponent - decreases with each update
        #
        x = pow(a, (s + 1) / 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e

        while True:
            t = b
            m = 0
            for m in xrange(r):
                if t == 1:
                    break
                t = pow(t, 2, p)

            if m == 0:
                return x

            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m

    @staticmethod
    def legendre_symbol(a, p):
        """ Compute the Legendre symbol a|p using
            Euler's criterion. p is a prime, a is
            relatively prime to p (if p divides
            a, then a|p = 0)

            Returns 1 if a has a square root modulo
            p, -1 otherwise.
        """
        ls = pow(a, (p - 1) / 2, p)
        return -1 if ls == p - 1 else ls

