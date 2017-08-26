#!/usr/bin/env python
# -*- coding: utf-8 -*-
from keychest.tls_domain_tools import TlsDomainTools
import random
import unittest

__author__ = 'dusanklinec'


class TlsDomainToolsTest(unittest.TestCase):
    """Simple TlsDomainTools tests"""

    def __init__(self, *args, **kwargs):
        super(TlsDomainToolsTest, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_ip_to_int(self):
        self.assertEqual(TlsDomainTools.ip_to_int('0.0.0.0'), 0)
        self.assertEqual(TlsDomainTools.ip_to_int('0.0.0.1'), 1)
        self.assertEqual(TlsDomainTools.ip_to_int('0.0.1.0'), 1 << 8)
        self.assertEqual(TlsDomainTools.ip_to_int('0.1.0.0'), 1 << 8*2)
        self.assertEqual(TlsDomainTools.ip_to_int('1.0.0.0'), 1 << 8*3)
        self.assertEqual(TlsDomainTools.ip_to_int('1.1.1.1'), (1 << 8*3) + (1 << 8*2) + (1 << 8) + 1)
        self.assertEqual(TlsDomainTools.ip_to_int('1.1.1.2'), (1 << 8*3) + (1 << 8*2) + (1 << 8) + 2)

        try:
            TlsDomainTools.ip_to_int('0.0.0')
            self.assertTrue(False, 'Should throw')
        except:
            pass

        try:
            TlsDomainTools.ip_to_int('0.0.0.0.0')
            self.assertTrue(False, 'Should throw')
        except:
            pass

        try:
            TlsDomainTools.ip_to_int('a.b.c.d')
            self.assertTrue(False, 'Should throw')
        except:
            pass

    def test_int_to_ip(self):
        self.assertEqual(TlsDomainTools.int_to_ip(0), '0.0.0.0')
        self.assertEqual(TlsDomainTools.int_to_ip(1), '0.0.0.1')
        self.assertEqual(TlsDomainTools.int_to_ip(2), '0.0.0.2')
        self.assertEqual(TlsDomainTools.int_to_ip(128), '0.0.0.128')
        self.assertEqual(TlsDomainTools.int_to_ip(1 << 8), '0.0.1.0')
        self.assertEqual(TlsDomainTools.int_to_ip(1 << 8*2), '0.1.0.0')
        self.assertEqual(TlsDomainTools.int_to_ip(1 << 8*3), '1.0.0.0')
        self.assertEqual(TlsDomainTools.int_to_ip((1 << 8*3) + 120), '1.0.0.120')

    def test_ip_iter(self):
        self.sub_test_iter('0.0.0.1',  '0.0.0.1')
        self.sub_test_iter('0.0.0.1',  '0.0.0.10')
        self.sub_test_iter('0.0.0.1',  '0.0.1.153')
        self.sub_test_iter('0.0.0.1',  '0.0.5.153')
        self.sub_test_iter('1.0.0.10', '1.0.1.15')
        self.sub_test_iter('1.0.0.10', '1.0.4.15')

        min_ip = 0
        max_ip = TlsDomainTools.ip_to_int('255.255.255.255')
        for test_idx in range(30):
            rand_start = random.randint(min_ip, max_ip)
            self.sub_test_iter(
                TlsDomainTools.int_to_ip(rand_start),
                TlsDomainTools.int_to_ip(rand_start + random.randint(0, 2000))
            )

    def sub_test_iter(self, ip_a, ip_b):
        """
        Sub test to iterate over IP - addresses
        :param ip_a:
        :param ip_b:
        :return:
        """
        ip_ai = TlsDomainTools.ip_to_int(ip_a)
        ip_bi = TlsDomainTools.ip_to_int(ip_b)

        ip_list = list(TlsDomainTools.iter_ips(ip_a,  ip_b))
        self.assertEqual(len(ip_list), 1 + ip_bi - ip_ai)
        self.assertEqual(len(list(set(ip_list))), 1 + ip_bi - ip_ai)
        self.assertIn(ip_a, ip_list)
        self.assertIn(ip_b, ip_list)

        for ip in ip_list:
            ipi = TlsDomainTools.ip_to_int(ip)
            self.assertGreaterEqual(ipi, ip_ai)
            self.assertLessEqual(ipi, ip_bi)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


