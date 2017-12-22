#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import unittest
import mock
import pkg_resources

# import keychest.util as util
from .. import util
from ..tls_handshake import TlsHandshaker
from . import MicroMock


__author__ = 'dusanklinec'


class TlsHandshakeTest(unittest.TestCase):
    """Simple TlsHandshakeTest tests"""

    def __init__(self, *args, **kwargs):
        super(TlsHandshakeTest, self).__init__(*args, **kwargs)

    def setUp(self):
        self.tester = TlsHandshaker()
        self.tester.timeout = 3
        self.tester.attempts = 3
        self.tester.tls_version = 'TLS_1_2'

    def tearDown(self):
        pass

    def _get_res(self, name):
        """
        Loads resource
        :param name:
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('data', name))
        return pkg_resources.resource_string(resource_package, resource_path)

    @mock.patch('socket.socket')
    def test_handshake_eb(self, mock_socket):
        sni = 'enigmabridge.com'
        mock_socket.return_value.recv.return_value = self._get_res('enigmabridge.com.resp.bin')
        ret = self.tester.try_handshake(host=sni, port=443, domain=sni, ecc=None)
        self._test_resp(ret)

    @mock.patch('socket.socket')
    def test_handshake_kc(self, mock_socket):
        sni = 'keychest.net'
        mock_socket.return_value.recv.return_value = self._get_res('keychest.net.resp.bin')
        ret = self.tester.try_handshake(host=sni, port=443, domain=sni, ecc=None)
        self._test_resp(ret)

    def _test_resp(self, ret):
        self.assertIsNotNone(ret)
        self.assertIsNotNone(ret.resp_record)
        self.assertIsNotNone(ret.certificates)
        self.assertTrue(len(ret.certificates) > 1)
        for x in ret.certificates:
            crt = util.load_x509_der(x)
            self.assertIsNotNone(crt)
            self.assertIsNotNone(util.try_get_cname(crt))
            self.assertIsNotNone(util.try_get_san(crt))
            self.assertIsNotNone(util.get_dn_string(crt.subject))
            self.assertIsNotNone(util.get_dn_string(crt.issuer))
            self.assertIsNotNone(util.try_get_fprint_sha256(crt))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


