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
import errors

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


class TlsIncomplete(errors.Error):
    """Incomplete data stream"""
    def __init__(self, message=None, cause=None):
        super(TlsIncomplete, self).__init__(message=message, cause=cause)


class TlsTimeout(errors.Error):
    """Handshake read timeout"""
    def __init__(self, message=None, cause=None):
        super(TlsTimeout, self).__init__(message=message, cause=cause)


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

        self.handshake_failure = False
        self.cipher_suite = None
        self.certificates = []

    def __repr__(self):
        return '<TlsHandshakeResult(time_start=%r, time_connected=%r, time_sent=%r, time_finished=%r, failure=%r, ' \
               'cipher_suite=%r, certificates_len=%r)>' \
               % (self.time_start, self.time_connected, self.time_sent, self.time_finished, self.handshake_failure,
                  self.cipher_suite, len(self.certificates))


class TLSExtSignatureAndHashAlgorithmFixed(PacketNoPayload):
    name = "TLS Extension Signature And Hash Algorithm"
    fields_desc = [
                   XFieldLenField("length", None, length_of="algs", fmt="H"),
                   PacketListField("algs", None, TLSSignatureHashAlgorithm, length_from=lambda x:x.length),
                  ]
bind_layers(TLSExtension, TLSExtSignatureAndHashAlgorithmFixed, {'type': TLSExtensionType.SIGNATURE_ALGORITHMS})


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
            TLSExtRenegotiationInfo(),

            TLSExtension() /
            TLSExtServerNameIndication(server_names=server_names),

            TLSExtension() /
            TLSExtSessionTicketTLS(),

            TLSExtension() /
            TLSExtSignatureAndHashAlgorithmFixed(algs=[
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA256, sig_alg=TLSSignatureAlgorithm.ECDSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA256, sig_alg=TLSSignatureAlgorithm.RSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA1, sig_alg=TLSSignatureAlgorithm.RSA),
            ]),

            TLSExtension() /
            TLSExtALPN(protocol_name_list=[TLSALPNProtocol(data="http/1.1")]),

            TLSExtension() /
            TLSExtECPointsFormat(ec_point_formats=[TLSEcPointFormat.UNCOMPRESSED]),

            TLSExtension() /
            TLSExtEllipticCurves(elliptic_curves=[
                TLSEllipticCurve.ECDH_X25519,
                TLSEllipticCurve.SECP256R1,
                TLSEllipticCurve.SECP384R1,
            ]),
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
        logger.debug(target)
        tls_ver = kwargs.get('tls_version', self.tls_version)
        timeout = float(kwargs.get('timeout', self.timeout))
        return_obj = TlsHandshakeResult()

        # create simple tcp socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)

            return_obj.time_start = time.time()
            s.connect(target)
            return_obj.time_connected = time.time()

            cl_hello = self._build_client_hello(host, tls_ver, **kwargs)
            return_obj.cl_hello = cl_hello

            s.sendall(str(cl_hello))
            return_obj.time_sent = time.time()

            self._read_while_finished(return_obj, s, timeout)

            return_obj.certificates = self._extract_certificates(return_obj.resp_record)

            return return_obj

        finally:
            util.silent_close(s)

    def _read_while_finished(self, return_obj, s, timeout):
        """
        Reads the socket until the whole handshake is done or timeouts
        :param return_obj: 
        :param s: 
        :return: 
        """
        resp_bin_acc = []
        resp_bin_tot = ''
        while True:
            resp_bin = self._recv_timeout(s, timeout=timeout, single_read=True)
            if len(resp_bin) == 0:
                raise TlsTimeout('Could not read more data')

            resp_bin_acc.append(resp_bin)
            resp_bin_tot = ''.join(resp_bin_acc)
            try:
                rec = SSL(resp_bin_tot)
                return_obj.resp_record = rec

                if self._is_failure(rec):
                    return_obj.handshake_failure = True
                    break

                if self._test_hello_done(rec):
                    break

            except TlsIncomplete as e:
                logger.debug(e)
                continue

        return_obj.resp_bin = resp_bin_tot
        return_obj.time_finished = time.time()
        return return_obj

    def _is_failure(self, packet):
        """
        True if SSL failure has been detected
        :param packet: 
        :return: 
        """
        if packet is None:
            raise ValueError('Packet is None')
        if not isinstance(packet, SSL):
            raise ValueError('Incorrect packet')

        for srec in packet.records:
            if srec.content_type != TLSContentType.ALERT:
                continue

            alert = srec.payload
            if not isinstance(alert, TLSAlert):
                logger.debug('TLS alert is not an alert')
                raise TlsIncomplete('Alert declared but no alert found')

            if alert.level == TLSAlertLevel.FATAL:
                return True

        return False

    def _test_hello_done(self, packet):
        """
        Tests if the whole server hello has been parser properly
        :param packet: 
        :return: 
        """
        if packet is None:
            raise ValueError('Packet is None')
        if not isinstance(packet, SSL):
            raise ValueError('Incorrect packet')

        for srec in packet.records:
            if srec.content_type != TLSContentType.HANDSHAKE:
                continue

            if not isinstance(srec.payload, TLSHandshake):
                raise TlsIncomplete('Handshake declared but no handshake found (hello)')

            if srec.payload.type == TLSHandshakeType.SERVER_HELLO_DONE:
                return True

        return False

    def _extract_certificates(self, packet):
        """
        Extracts server certificates from the response
        :param packet: 
        :return: 
        """
        if packet is None:
            raise ValueError('Packet is None')
        if not isinstance(packet, SSL):
            raise ValueError('Incorrect packet')

        certificates = []
        for srec in packet.records:
            if srec.content_type != TLSContentType.HANDSHAKE:
                continue

            if not isinstance(srec.payload, TLSHandshake):
                raise TlsIncomplete('Handshake declared but no handshake found (cert)')

            if srec.payload.type == TLSHandshakeType.CERTIFICATE:
                cert_list_rec = srec.payload.payload
                certificates_rec = cert_list_rec.certificates
                certificates += [str(x.data) for x in certificates_rec]

        return certificates

    def _recv_timeout(self, the_socket, timeout=3, single_read=False):
        """
        Reading data from the socket with timeout (multiple packet read)
        :param the_socket: 
        :param timeout: 
        :return: 
        """
        # make socket non blocking
        the_socket.setblocking(0)

        # total data partwise in an array
        total_data = []
        data = ''

        # beginning time
        begin = time.time()
        while 1:
            # if you got some data, then break after timeout
            if total_data and time.time() - begin > timeout:
                break

            # if you got no data at all, wait a little longer, twice the timeout
            elif time.time() - begin > timeout * 2:
                break

            # recv something
            try:
                data = the_socket.recv(8192)
                if data:
                    total_data.append(data)
                    # change the beginning time for measurement
                    begin = time.time()
                    if single_read:
                        return ''.join(total_data)
                else:
                    # sleep for sometime to indicate a gap
                    time.sleep(0.1)
            except:
                pass

        # join all parts to make final string
        return ''.join(total_data)


if __name__ == '__main__':
    coloredlogs.install(level=logging.DEBUG)

    target = 'enigmabridge.com'
    if len(sys.argv) > 1:
        target = sys.argv[1]

    tester = TlsHandshaker()
    tester.timeout = 3
    tester.attempts = 3
    tester.tls_version = 'TLS_1_1'

    logger.info('Testing %s' % target)
    ret = tester.try_handshake(host=target)

    # print('Client hello: ')
    # print(ret.cl_hello.show())
    # print('-' * 80)

    print(ret.resp_record.show())
    print('-' * 80)

    # print(repr(ret.resp_bin))
    # print('-' * 80)

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






