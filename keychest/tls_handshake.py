#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import time

import coloredlogs
import requests
import util
import datetime
import traceback
import base64
import trace_logger

import scapy
from scapy.layers.ssl_tls import *
import socket


logger = logging.getLogger(__name__)


# Default cipher suites provided in client hello
DEFAULT_CIPHER_SUITES = [
    TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA256,
    TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA,

    TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
    TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA256,

    TLSCipherSuite.RSA_WITH_3DES_EDE_CBC_SHA,

    TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA,
    TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA,
    TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA256,
    TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA256,

    TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA,
    TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA256,

    TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,

    TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256,

    TLSCipherSuite.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
]


class TlsHandshakeResult(object):
    """
    Result of the handshake test
    """
    def __init__(self):
        self.time_start = None
        self.time_connected = None
        self.time_sent = None
        self.time_finished = None

        self.cl_hello = None
        self.resp_bin = None
        self.resp_record = None

        self.cipher_suite = None
        self.certificates = []


class TlsHandshaker(object):
    """
    Object performing simple TLS handshake, parsing the results
    """
    DEFAULT_TLS = "TLS_1_1"
    DEFAULT_ATTEMPTS = 3

    def __init__(self, timeout=10, tls_version=None, attempts=None, **kwargs):
        self.timeout = timeout
        self.tls_version = util.defval(tls_version, self.DEFAULT_TLS)
        self.attempts = int(util.defval(attempts, self.DEFAULT_ATTEMPTS))
        self.trace_logger = trace_logger.Tracelogger(logger)

    def _build_client_hello(self, hostname, tls_ver, **kwargs):
        """
        Builds client hello packet for the handshake init
        :param kwargs: 
        :return: 
        """
        cl_hello = TLSClientHello(version=tls_ver)
        cl_hello.cipher_suites = DEFAULT_CIPHER_SUITES

        if not isinstance(hostname, types.ListType):
            hostname = [hostname]

        server_names = [TLSServerName(data=x) for x in hostname]

        # SNI
        cl_hello.extensions = [
            TLSExtension() /
            TLSExtServerNameIndication(server_names=server_names)
        ]

        # Complete record with handshake / client hello
        p = TLSRecord(version=tls_ver) / TLSHandshake() / cl_hello
        return p

    def try_handshake(self, host, port=443, attempts=None, sleep_fnc=None, **kwargs):
        """
        Attempts for handshake
        :param host: 
        :param port: 
        :param attempts: 
        :param kwargs: 
        :return: 
        """
        attempts = util.defval(attempts, self.attempts)
        for attempt in range(attempts):
            try:
                return self.handshake(host=host, port=port, **kwargs)

            except Exception as e:
                logger.debug('Exception on handshake[%s]: %s' % (attempt, e))
                if attempt + 1 >= attempts:
                    raise
                if sleep_fnc is not None:
                    time.sleep(sleep_fnc(attempt))
                else:
                    time.sleep(0.5)

    def handshake(self, host, port=443, **kwargs):
        """
        Performs the handshake
        :param host: 
        :param port: 
        :return: 
        """
        target = (host, port)
        tls_ver = kwargs.get('tls_version', self.tls_version)
        timeout = float(kwargs.get('timeout', self.timeout))
        return_obj = TlsHandshakeResult()

        # create simple tcp socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)

            return_obj.time_start = time.time()
            s.connect(target)

            cl_hello = self._build_client_hello(host, tls_ver, **kwargs)
            return_obj.cl_hello = cl_hello

            s.sendall(str(cl_hello))
            return_obj.time_sent = time.time()

            resp_bin = s.recv(65536*4)
            return_obj.time_finished = time.time()

            # rec = TLSRecord(resp)
            rec = SSL(resp_bin)
            return_obj.resp_record = rec

            # certificate extract
            for srec in rec.records:
                try:
                    is_handshake = srec.content_type == TLSContentType.HANDSHAKE
                    is_certificate = is_handshake and srec.payload.type == TLSHandshakeType.CERTIFICATE
                    if is_certificate:
                        cert_list_rec = srec.payload.payload
                        certificates_rec = cert_list_rec.certificates
                        return_obj.certificates = [str(x.data) for x in certificates_rec]

                except AttributeError as ae:
                    logger.debug('Attribute error on tls handshake cert get: %s' % ae)
                    self.trace_logger.log(ae)
                    logger.debug(srec.show())
                    raise

            return return_obj

        finally:
            util.silent_close(s)


if __name__ == '__main__':
    coloredlogs.install(level=logging.DEBUG)

    target = 'root.cz'
    if len(sys.argv) > 1:
        target = sys.argv[1]

    tester = TlsHandshaker()
    tester.timeout = 5
    tester.tls_version = 'TLS_1_1'

    logger.info('Testing %s' % target)
    ret = tester.try_handshake(host=target)

    print ret.resp_record.show()
    print '-' * 80

    print 'Certificates: \n'
    for x in ret.certificates:
        crt = util.load_x509_der(x)
        cname = util.try_get_cname(crt)
        san = util.try_get_san(crt)
        subject = util.get_dn_string(crt.subject)
        issuer = util.get_dn_string(crt.issuer)

        print(' - CN: %s' % cname)
        print(' - Domain names: %s' % json.dumps(san))
        print(' - Issuer:  %s' % issuer)
        print(' - Subject: %s' % subject)
        print(' - Fprint sha1:   %s' % util.try_get_fprint_sha1(crt))
        print(' - Fprint sha256: %s' % util.try_get_fprint_sha256(crt))
        print('\n')
        print(base64.b64encode(x))

        print('. ' * 40)






