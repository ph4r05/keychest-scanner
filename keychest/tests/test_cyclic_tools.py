#!/usr/bin/env python
# -*- coding: utf-8 -*-
from keychest.cyclic_tools import CyclicTools
import unittest

__author__ = 'dusanklinec'


class CyclicToolsTest(unittest.TestCase):
    """Simple tests of cyclic group tools"""

    def __init__(self, *args, **kwargs):
        super(CyclicToolsTest, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_prime(self):
        self.assertEqual(CyclicTools.prime3(2), True)
        self.assertEqual(CyclicTools.prime3(3), True)
        self.assertEqual(CyclicTools.prime3(4), False)
        self.assertEqual(CyclicTools.prime3(67), True)
        self.assertEqual(CyclicTools.prime3(88), False)
        self.assertEqual(CyclicTools.prime3(8831), True)
        self.assertEqual(CyclicTools.prime3(15487469), True)
        self.assertEqual(CyclicTools.prime3(179426549), True)
        self.assertEqual(CyclicTools.prime3(179426548), False)
        self.assertEqual(CyclicTools.prime3(961748941), True)

    def test_next_prime(self):
        self.assertEqual(CyclicTools.next_prime(4), 5)
        self.assertEqual(CyclicTools.next_prime(18), 19)
        self.assertEqual(CyclicTools.next_prime(179426548), 179426549)
        self.assertEqual(CyclicTools.next_prime(179426547), 179426549)
        self.assertEqual(CyclicTools.next_prime(179426549), 179426549)

    def test_prime_factors(self):
        self.assertListEqual(CyclicTools.prime_factors(2*2*3*3*5*11*17), [2, 2, 3, 3, 5, 11, 17])
        self.assertListEqual(CyclicTools.prime_factors(2*11*17*19*67), [2, 11, 17, 19, 67])
        self.assertListEqual(CyclicTools.prime_factors(67), [67])
        self.assertListEqual(CyclicTools.prime_factors(67), [67])
        self.assertListEqual(CyclicTools.prime_factors(15487469), [15487469])

    def test_generators(self):
        self.sub_gen(23)  # sophie-germain
        self.sub_gen(67)
        self.sub_gen(1721)
        self.sub_gen(1723)
        self.sub_gen(3217)
        self.sub_gen(191)  # sophie-germain
        self.sub_gen(911)  # sophie-germain
        self.sub_gen(953)  # sophie-germain

    def sub_gen(self, p):
        """
        Generator test - find random one, generate the group with it.
        :param p:
        :return:
        """
        self.assertEqual(CyclicTools.prime3(p), True)  # for easier Phi(x) computation require p

        phi = p - 1
        g = CyclicTools.find_generator(p)

        group = list(CyclicTools.generate(p, g))

        # basic length test
        self.assertEqual(len(group), phi)

        # the whole group, no duplicates
        self.assertEqual(len(list(set(group))), phi)

        # no zero, unit
        self.assertNotIn(0, group)
        self.assertIn(1, group)

        self.assertLessEqual(max(group), phi)
        self.assertGreater(min(group), 0)

    def test_cyclic(self):
        self.sub_cyclic(10)
        self.sub_cyclic(11)
        self.sub_cyclic(23)
        self.sub_cyclic(25)
        self.sub_cyclic(67)
        self.sub_cyclic(953)
        self.sub_cyclic(1721)
        self.sub_cyclic(25, sophie=True)
        self.sub_cyclic(67, randomize=True)
        self.sub_cyclic(23, randomize=True)
        self.sub_cyclic(25, randomize=True)
        self.sub_cyclic(953, randomize=True)
        self.sub_cyclic(953, randomize=True)

    def sub_cyclic(self, n, sophie=False, randomize=False):
        """
        Tests sub-cyclic generator for given n
        :return:
        """
        cl = CyclicTools(n)
        cl.init(sophie=sophie, random_offset=randomize)
        group = list(cl.iter())

        self.assertEqual(len(group), n)
        self.assertEqual(len(list(set(group))), n)
        self.assertIn(0, group)
        self.assertIn(1, group)
        self.assertLessEqual(max(group), n)
        self.assertGreaterEqual(min(group), 0)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


