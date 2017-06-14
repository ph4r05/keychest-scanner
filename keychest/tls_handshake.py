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
from scapy.packet import NoPayload
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
    0xc02c,  # TLSCipherSuite.ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    0xc030,  # TLSCipherSuite.ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    0xcca9,
    0xcca8,

    TLSCipherSuite.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
]


class TlsIncomplete(errors.Error):
    """Incomplete data stream"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsIncomplete, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class TlsTimeout(errors.Error):
    """Handshake read timeout"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsTimeout, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class TlsException(errors.Error):
    """General exception"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsException, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class TlsHandshakeErrors(object):
    """
    Basic handshake errors
    """
    CONN_ERR = 2
    READ_TO = 3
    HANDSHAKE_ERR = 1

    def __init__(self):
        pass


class TlsHandshakeResult(object):
    """
    Result of the handshake test
    """
    def __init__(self):
        self.host = None
        self.port = None
        self.domain = None
        self.ip = None

        self.time_start = None
        self.time_connected = None
        self.time_sent = None
        self.time_finished = None
        self.time_failed = None
        self.tls_version = None

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


class TLSExtChannelId(PacketNoPayload):
    name = "TLS Extension channel id"
    fields_desc = [StrLenField("data", '', length_from=lambda x:x.underlayer.length),]


class TLSExt2a2a(PacketNoPayload):
    name = "ext-2a2a"
    fields_desc = [StrLenField("data", '', length_from=lambda x:x.underlayer.length),]


class TLSExt4a4a(PacketNoPayload):
    name = "ext-4a4a"
    fields_desc = [StrLenField("data", '', length_from=lambda x:x.underlayer.length),]


class TLSExtExtendedMasterSecret(PacketNoPayload):
    name = "TLS Extension ExtendedMasterSecret"
    fields_desc = [StrLenField("data", '', length_from=lambda x: x.underlayer.length), ]


bind_layers(TLSExtension, TLSExtSignatureAndHashAlgorithmFixed, {'type': TLSExtensionType.SIGNATURE_ALGORITHMS})
bind_layers(TLSExtension, TLSExtChannelId, {'type': 0x7550})
bind_layers(TLSExtension, TLSExt2a2a, {'type': 0x2a2a})
bind_layers(TLSExtension, TLSExt4a4a, {'type': 0x4a4a})
bind_layers(TLSExtension, TLSExtExtendedMasterSecret, {'type': 0x0017})


class TlsHandshaker(object):
    """
    Object performing simple TLS handshake, parsing the results
    """
    DEFAULT_TLS = "TLS_1_2"
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
            TLSExt4a4a(),

            TLSExtension() /
            TLSExtRenegotiationInfo(),

            TLSExtension() /
            TLSExtServerNameIndication(server_names=server_names),

            TLSExtension() /
            TLSExtExtendedMasterSecret(),

            TLSExtension() /
            TLSExtSessionTicketTLS(),

            TLSExtension() /
            TLSExtSignatureAndHashAlgorithmFixed(algs=[
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA256, sig_alg=TLSSignatureAlgorithm.ECDSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA256, sig_alg=TLSSignatureAlgorithm.RSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA1, sig_alg=TLSSignatureAlgorithm.RSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA384, sig_alg=TLSSignatureAlgorithm.ECDSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA384, sig_alg=TLSSignatureAlgorithm.RSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA512, sig_alg=TLSSignatureAlgorithm.ECDSA),
                TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA512, sig_alg=TLSSignatureAlgorithm.RSA),
                TLSSignatureHashAlgorithm(hash_alg=0x8, sig_alg=0x6),
                TLSSignatureHashAlgorithm(hash_alg=0x8, sig_alg=0x5),
                TLSSignatureHashAlgorithm(hash_alg=0x8, sig_alg=0x4)
            ]),

            TLSExtension() /
            TLSExtALPN(protocol_name_list=[TLSALPNProtocol(data="http/1.1")]),

            TLSExtension() /
            TLSExtChannelId(),

            TLSExtension() /
            TLSExtECPointsFormat(ec_point_formats=[TLSEcPointFormat.UNCOMPRESSED]),

            TLSExtension() /
            TLSExtEllipticCurves(elliptic_curves=[
                TLSEllipticCurve.ECDH_X25519,
                TLSEllipticCurve.SECP256R1,
                TLSEllipticCurve.SECP384R1,
                0x6a6a
            ]),

            TLSExtension() /
            TLSExt2a2a(),
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
        logger.debug('Connecting to: %s' % (target, ))
        tls_ver = kwargs.get('tls_version', self.tls_version)
        domain_sni = kwargs.get('domain', host)
        timeout = float(kwargs.get('timeout', self.timeout))

        return_obj = TlsHandshakeResult()
        return_obj.tls_version = tls_ver
        return_obj.host = host
        return_obj.port = port
        return_obj.domain = domain_sni

        # create simple tcp socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)

            return_obj.time_start = time.time()
            try:
                s.connect(target)
                return_obj.time_connected = time.time()
                return_obj.ip = self._try_get_peer_ip(s)

            except Exception as e:
                logger.debug('Exception during connect: %s' % e)
                self.trace_logger.log(e)
                return_obj.handshake_failure = TlsHandshakeErrors.CONN_ERR
                return_obj.time_failed = time.time()
                return_obj.ip = self._try_get_peer_ip(s)

                raise TlsTimeout('Connect timeout', e, scan_result=return_obj)

            cl_hello = self._build_client_hello(domain_sni, tls_ver, **kwargs)
            return_obj.cl_hello = cl_hello

            s.sendall(str(cl_hello))
            return_obj.time_sent = time.time()

            self._read_while_finished(return_obj, s, timeout)

            return_obj.certificates = self._extract_certificates(return_obj.resp_record)

            return return_obj

        except TlsTimeout:
            raise
        except TlsIncomplete:
            raise
        except Exception as e:
            logger.debug('Generic exception on tls scan %s' % e)
            self.trace_logger.log(e)

            raise TlsException('Generic exception', e, scan_result=return_obj)

        finally:
            util.silent_close(s)

    def _try_get_peer_ip(self, s):
        """
        Tries to extract IP address of the remote peer from the socket
        :param s:
        :return:
        """
        try:
            return s.getpeername()[0]
        except Exception as e:
            return None

    def _read_while_finished(self, return_obj, s, timeout):
        """
        Reads the socket until the whole handshake is done or timeouts
        :param return_obj: 
        :param s: 
        :return: 
        """
        resp_bin_acc = []
        resp_bin_tot = ''
        read_more = True
        while read_more:
            resp_bin = self._recv_timeout(s, timeout=timeout, single_read=True)
            if len(resp_bin) == 0:
                read_more = False

            if not read_more and len(resp_bin_tot) == 0:  # no data received at all -> timeout
                    return_obj.handshake_failure = TlsHandshakeErrors.READ_TO
                    return_obj.time_failed = time.time()
                    raise TlsTimeout('Could not read any data', scan_result=return_obj)

            resp_bin_acc.append(resp_bin)
            resp_bin_tot = ''.join(resp_bin_acc)
            try:
                rec = SSL(resp_bin_tot)
                return_obj.resp_record = rec

                if self._is_failure(rec):
                    return_obj.handshake_failure = TlsHandshakeErrors.HANDSHAKE_ERR
                    return_obj.time_failed = time.time()
                    break

                if self._test_hello_done(rec):
                    break

            except TlsIncomplete as e:
                logger.debug(e)
                if not read_more:
                    raise

        return_obj.resp_bin = resp_bin_tot
        return_obj.time_finished = time.time()
        return return_obj

    def _search_payload(self, payload):
        """
        Returns true if the payload is a processable payload, not sentinel scapy.packet.NoPayload
        :param payload: 
        :return: 
        """
        return payload is not None \
               and type(payload) is not PacketNoPayload \
               and type(payload) is not NoPayload

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

    def _test_hello_done(self, packet, recursive_search=True):
        """
        Tests if the whole server hello has been parser properly
        :param packet: 
        :param recursive_search: 
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

            cur_payload = srec.payload
            while self._search_payload(cur_payload):
                if isinstance(cur_payload, TLSHandshake) and cur_payload.type == TLSHandshakeType.SERVER_HELLO_DONE:
                   return True
                if not recursive_search:
                    return False
                cur_payload = cur_payload.payload

        return False

    def _extract_certificates(self, packet, recursive_search=True):
        """
        Extracts server certificates from the response
        :param packet: 
        :param recursive_search: 
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

            cur_payload = srec.payload
            while self._search_payload(cur_payload):
                if isinstance(cur_payload, TLSHandshake) and cur_payload.type == TLSHandshakeType.CERTIFICATE:
                    cert_list_rec = srec.payload.payload
                    certificates_rec = cert_list_rec.certificates
                    certificates += [str(x.data) for x in certificates_rec]
                if not recursive_search:
                    return False
                cur_payload = cur_payload.payload

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

            # if you got no data at all, the same
            elif time.time() - begin > timeout:
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

    port = 443
    target = 'enigmabridge.com'
    if len(sys.argv) > 1:
        target = sys.argv[1]

    if ':' in target:
        target, port = target.split(':', 1)
        port = int(port)

    tester = TlsHandshaker()
    tester.timeout = 3
    tester.attempts = 3
    tester.tls_version = 'TLS_1_2'

    logger.info('Testing %s:%s' % (target, port))
    ret = tester.try_handshake(host=target, port=port)

    # print('Client hello: ')
    # print(ret.cl_hello.show())
    # print('-' * 80)

    print(ret.resp_record.show())
    print('-' * 80)

    # print(repr(ret.resp_bin))
    # print('-' * 80)

    print('Certificates (%d) : \n' % len(ret.certificates))
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






