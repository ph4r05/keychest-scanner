#!/usr/bin/env python
# -*- coding: utf-8 -*-
import keychest.util as util
import keychest.util_cert as util_cert
from keychest.tls_domain_tools import TlsDomainTools
import random
import base64
import unittest
import pkg_resources


__author__ = 'dusanklinec'


class CertUtilTest(unittest.TestCase):
    """Simple CertUtilTest tests"""

    def __init__(self, *args, **kwargs):
        super(CertUtilTest, self).__init__(*args, **kwargs)
        self.certs = []

    def setUp(self):
        """
        Loads testing certs
        :return:
        """
        for cname in ['cert01.pem', 'cert02.pem', 'cert03.pem']:
            self.certs.append(self._get_res(cname))

    def tearDown(self):
        """
        Cleanup
        :return:
        """

    def _get_res(self, name):
        """
        Loads resource
        :param name:
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('data', name))
        return pkg_resources.resource_string(resource_package, resource_path)

    def _ossl(self, x):
        """
        Openssl hex cleanup
        :param x:
        :return:
        """
        return str(x).replace(':', '')

    def test_parse_cert(self):
        """
        Test certificate parsing
        :return:
        """
        for cert in self.certs:
            self.assertIsNotNone(util.load_x509(cert))

    def test_parse_cert_der(self):
        """
        Test certificate parsing
        :return:
        """
        for cert in self.certs:
            self.assertIsNotNone(util.load_x509_der(util.pem_to_der(cert)))

    def test_is_ca(self):
        """
        Is CA flag testing
        :return:
        """
        certs = [util.load_x509(cert) for cert in self.certs]
        self.assertTrue(util.try_is_ca(certs[0]))
        self.assertFalse(util.try_is_ca(certs[1]))
        self.assertTrue(util.try_is_ca(certs[2]))

    def test_self_signed(self):
        """
        Self signed test
        :return:
        """
        certs = [util.load_x509(cert) for cert in self.certs]
        self.assertFalse(util.try_is_self_signed(certs[0]))
        self.assertFalse(util.try_is_self_signed(certs[1]))
        self.assertTrue(util.try_is_self_signed(certs[2]))

    def test_subject_key_id(self):
        """
        X509v3 Subject Key Identifier
        :return:
        """
        certs = [util.load_x509(cert) for cert in self.certs]
        subj_ids = [util.try_get_subject_key_identifier(x, compute_if_not_present=False) for x in certs]
        computed_subj_ids = [util.try_compute_subject_key_identifier(x, False) for x in certs]

        self.assertEqual(util.b16encode(subj_ids[0]),
                         self._ossl('A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1'))
        self.assertEqual(util.b16encode(subj_ids[1]),
                         self._ossl('FF:FB:9D:B7:99:6C:1E:F6:47:0A:6F:CA:46:DB:91:6C:60:02:BE:94'))
        self.assertEqual(util.b16encode(subj_ids[2]),
                         self._ossl('7B:52:06:B4:C2:C2:D1:28:CB:71:A4:AC:3A:C1:80:94:57:7C:35:AD'))

        self.assertEqual(subj_ids, computed_subj_ids)

    def test_auth_key_id(self):
        """
        X509v3 Authority Key Identifier
        :return:
        """
        certs = [util.load_x509(cert) for cert in self.certs]
        auth_ids = [util.try_get_authority_key_identifier(x) for x in certs]

        self.assertEqual(util.b16encode(auth_ids[0]),
                         self._ossl('C4:A7:B1:A4:7B:2C:71:FA:DB:E1:4B:90:75:FF:C4:15:60:85:89:10'))
        self.assertEqual(util.b16encode(auth_ids[1]),
                         self._ossl('A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1'))
        self.assertEqual(util.b16encode(auth_ids[2]),
                         self._ossl('7B:52:06:B4:C2:C2:D1:28:CB:71:A4:AC:3A:C1:80:94:57:7C:35:AD'))

    def test_ev(self):
        """
        Extended validation test
        :return:
        """
        for cname in ['cert04.pem']:
            self.certs.append(self._get_res(cname))

        certs = [util.load_x509(cert) for cert in self.certs]
        ev_status = [util_cert.cert_is_ev(cert) for cert in certs]
        self.assertEqual(ev_status, [False, False, False, True])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


