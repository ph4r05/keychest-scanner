#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import json
import logging

import coloredlogs

try:
    import scapy.all as scapy
except ImportError:
    import scapy

from scapy.packet import NoPayload

try:
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    from scapy.layers.ssl_tls import *

from keychest import errors
from keychest import trace_logger
from keychest import util
from keychest.tls_domain_tools import TlsDomainTools

logger = logging.getLogger(__name__)


class TlsIncomplete(errors.Error):
    """Incomplete data stream, invalid read"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsIncomplete, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class TlsTimeout(errors.Error):
    """Handshake read timeout"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsTimeout, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class TlsResolutionError(errors.Error):
    """Handshake read timeout"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsResolutionError, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class TlsException(errors.Error):
    """General exception"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsException, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class TlsHandshakeFailure(TlsException):
    """Handshake failure - probably not TLS compliant, no server-done or fatal alert"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsHandshakeFailure, self).__init__(message=message, cause=cause, scan_result=scan_result)


class TlsHandshakeAbort(TlsException):
    """Handshake error - alert"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(TlsHandshakeAbort, self).__init__(message=message, cause=cause, scan_result=scan_result)


class TlsHandshakeAlert(object):
    """
    Simple handshake alert wrapper
    """
    def __init__(self, level=None, desc=None, alert=None):
        self.alert = alert  # type: TLSAlert
        self.level = level  # type: int
        self.desc = desc  # type: int

    def __repr__(self):
        return '<TlsHandshakeAlert(%r, %r)>' % (self.level, self.desc)

    def __str__(self):
        return 'Alert level=%s: desc=%s' % (self.level, self.desc)


class TlsHandshakeErrors(object):
    """
    Basic handshake errors
    """
    CONN_ERR = 2       # Connection error
    READ_TO = 3        # Read timeout
    HANDSHAKE_ERR = 1  # Handshake failed according to the TLS protocol - alert
    GAI_ERROR = 4      # DNS resolution problem
    NO_TLS = 5         # Not compliant to TLS protocol (no alert nor server done)

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
        self.connect_target = None
        self.socket_family = None
        self.dns_results = None

        self.time_start = None
        self.time_connected = None
        self.time_sent = None
        self.time_finished = None
        self.time_failed = None
        self.tls_version = None

        self.cl_hello = None
        self.resp_bin = None
        self.resp_record = None

        self.dns_failure = False
        self.handshake_failure = False
        self.alert = None  # type: TlsHandshakeAlert
        self.cipher_suite = None
        self.certificates = []

    def __repr__(self):
        return '<TlsHandshakeResult(time_start=%r, time_connected=%r, time_sent=%r, time_finished=%r, failure=%r, ' \
               'dns_failure=%r, cipher_suite=%r, certificates_len=%r, ip=%r, socket=%r)>' \
               % (self.time_start, self.time_connected, self.time_sent, self.time_finished, self.handshake_failure,
                  self.dns_failure, self.cipher_suite, len(self.certificates), self.ip, self.socket_family)


TLS_ELLIPTIC_CURVES = registry.SUPPORTED_GROUPS_REGISTRY
TLSEllipticCurve = EnumStruct(TLS_ELLIPTIC_CURVES)


class TLSSignatureHashAlgorithm(PacketNoPayload):
    name = "TLS Signature Hash Algorithm Pair"
    fields_desc = [
                   ByteEnumField("hash_alg", None, TLS_HASH_ALGORITHMS),
                   ByteEnumField("sig_alg", None, TLS_SIGNATURE_ALGORITHMS),
                  ]


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

    def _get_cipher_suites(self, ecc=True, rsa=True, dhe=True, dss=True, ecdhe=True):
        """
        Returns list of ciphersuites for use in TLS handshake
        :param ecc:
        :param rsa:
        :param dhe:
        :param dss:
        :param ecdhe:
        :return:
        """
        # Default cipher suites provided in client hello
        return util.compact([
            TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA256 if rsa else None,
            TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA if rsa else None,

            TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA if rsa else None,
            TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA256 if rsa else None,

            TLSCipherSuite.RSA_WITH_3DES_EDE_CBC_SHA if rsa else None,

            TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA if dhe and rsa else None,
            TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA if dhe and rsa else None,
            TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA256 if dhe and rsa else None,
            TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA256 if dhe and rsa else None,

            TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA if ecdhe and rsa else None,
            TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256 if ecdhe and rsa else None,
            TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA if ecdhe and rsa else None,
            TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256 if ecdhe and rsa else None,
            TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA if ecdhe and ecc else None,
            TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 if ecdhe and ecc else None,

            TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 if ecdhe and ecc else None,
            TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256 if ecdhe and rsa else None,
            0xc02c if ecdhe and ecc else None,  # TLSCipherSuite.ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            0xc030 if ecdhe and rsa else None,  # TLSCipherSuite.ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            0xcca9,
            0xcca8,

            TLSCipherSuite.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 if ecdhe and ecc else None,

            TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA if dhe and dss else None,
            TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA256 if dhe and dss else None,
        ])

    def _build_client_hello(self, hostname, tls_ver, ecc=None, **kwargs):
        """
        Builds client hello packet for the handshake init
        :param tls_ver:
        :param ecc: if None both RSA & ECC are allowed, otherwise either ECC or RSA
        :param kwargs:
        :return:
        """
        f_ecc = ecc is None or ecc
        f_rsa = ecc is None or not ecc
        cl_hello = TLSClientHello(version=tls_ver)
        cl_hello.cipher_suites = self._get_cipher_suites(ecc=f_ecc, rsa=f_rsa)

        if not isinstance(hostname, list):
            hostname = [hostname]

        server_names = [TLSServerName(data=x) for x in hostname]

        signature_algs = util.compact([
            TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA256, sig_alg=TLSSignatureAlgorithm.ECDSA) if f_ecc else None,
            TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA256, sig_alg=TLSSignatureAlgorithm.RSA) if f_rsa else None,
            TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA1, sig_alg=TLSSignatureAlgorithm.RSA) if f_rsa else None,
            TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA384, sig_alg=TLSSignatureAlgorithm.ECDSA) if f_ecc else None,
            TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA384, sig_alg=TLSSignatureAlgorithm.RSA) if f_rsa else None,
            TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA512, sig_alg=TLSSignatureAlgorithm.ECDSA) if f_ecc else None,
            TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA512, sig_alg=TLSSignatureAlgorithm.RSA) if f_rsa else None,
            TLSSignatureHashAlgorithm(hash_alg=0x8, sig_alg=0x6),
            TLSSignatureHashAlgorithm(hash_alg=0x8, sig_alg=0x5),
            TLSSignatureHashAlgorithm(hash_alg=0x8, sig_alg=0x4)
        ])

        curves = TLSExtEllipticCurves(named_group_list=[
            TLSSupportedGroup.ECDH_X25519,
            TLSSupportedGroup.SECP256R1,
            TLSSupportedGroup.SECP384R1,
            0x6a6a
        ]) if util.is_py3() else TLSExtEllipticCurves(elliptic_curves=[
            TLSEllipticCurve.ECDH_X25519,
            TLSEllipticCurve.SECP256R1,
            TLSEllipticCurve.SECP384R1
        ])

        # SNI
        cl_hello.extensions = util.compact([
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
            TLSExtSignatureAndHashAlgorithmFixed(algs=signature_algs),

            TLSExtension() /
            TLSExtALPN(protocol_name_list=[TLSALPNProtocol(data="http/1.1")]),

            TLSExtension() /
            TLSExtChannelId(),

            (TLSExtension() /
            TLSExtECPointsFormat(ec_point_formats=[TLSEcPointFormat.UNCOMPRESSED])) if f_ecc else None,

            (TLSExtension() /
            curves) if f_ecc else None,

            TLSExtension() /
            TLSExt2a2a(),
        ])

        # Complete record with handshake / client hello
        try:
            p = TLSRecord() / TLSHandshakes(handshakes=[TLSHandshake() / cl_hello])
        except NameError:
            p = TLSRecord(content_type=TLSContentType.HANDSHAKE) / TLSHandshake() / cl_hello
        return p

    def try_handshake(self, host, port=443, attempts=None, sleep_fnc=None, **kwargs):
        """
        Attempts for handshake
        :param host: 
        :param port: 
        :param attempts: 
        :param kwargs: 
        :return:
        :rtype TlsHandshakeResult
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
        :rtype TlsHandshakeResult
        """
        return_obj = TlsHandshakeResult()
        return_obj.connect_target = (host, port)
        tls_ver = kwargs.get('tls_version', self.tls_version)
        domain_sni = util.defval(kwargs.get('domain', host), host)
        timeout = float(kwargs.get('timeout', self.timeout))

        return_obj.tls_version = tls_ver
        return_obj.host = host
        return_obj.port = port
        return_obj.domain = domain_sni
        return_obj.socket_family = socket.AF_INET

        if TlsDomainTools.is_ip(host):
            return_obj.ip = host

            if TlsDomainTools.is_valid_ipv6_address(host):
                return_obj.socket_family = socket.AF_INET6
        else:
            self._resolve_ip(return_obj)

        # create simple tcp socket
        s = socket.socket(return_obj.socket_family, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)

            return_obj.time_start = time.time()
            try:
                logger.debug('Connecting to: %s, %s, %s' % (return_obj.connect_target, host, domain_sni))
                s.connect(return_obj.connect_target)

                return_obj.time_connected = time.time()
                return_obj.ip = util.defval(self._try_get_peer_ip(s), return_obj.ip)

            except Exception as e:
                logger.debug('Exception during connect %s - %s: %s' % (return_obj.connect_target, domain_sni, e))
                self.trace_logger.log(e)
                return_obj.handshake_failure = TlsHandshakeErrors.CONN_ERR
                return_obj.time_failed = time.time()
                return_obj.ip = util.defval(self._try_get_peer_ip(s), return_obj.ip)

                raise TlsTimeout('Connect timeout on %s - %s' % (return_obj.connect_target, domain_sni), e, scan_result=return_obj)

            cl_hello = self._build_client_hello(domain_sni, tls_ver, **kwargs)
            return_obj.cl_hello = cl_hello

            hello_packet = bytes(cl_hello)
            s.sendall(hello_packet)
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

    def _resolve_ip(self, res):
        """
        Resolves IP address of the target
        :param res:
        :return:
        """
        try:
            results = socket.getaddrinfo(res.host, res.port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            if len(results) == 0:
                raise errors.Error('DNS returned empty result')

            res.dns_results = results
            res.connect_target = results[0][4]
            res.socket_family = results[0][0]

        except Exception as e:
            res.dns_failure = e
            res.handshake_failure = TlsHandshakeErrors.GAI_ERROR
            res.socket_family = None
            res.connect_target = None

            raise TlsResolutionError('DNS resolution error on %s - %s' % (res.host, res.domain), e, scan_result=res)

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
            # resp_bin_tot = util.join_buff(resp_bin_acc)
            resp_bin_tot = b''.join(resp_bin_acc)

            try:
                # rec = SSL(resp_bin_tot)
                rec = TLS(resp_bin_tot)

                return_obj.resp_record = rec

                alert_record = self._get_failure(rec)
                if alert_record is not None:
                    return_obj.handshake_failure = TlsHandshakeErrors.HANDSHAKE_ERR
                    return_obj.time_failed = time.time()
                    return_obj.alert = TlsHandshakeAlert(level=alert_record.level, desc=alert_record.description, alert=alert_record)
                    raise TlsHandshakeAbort('Handshake alert received: %s' % return_obj.alert, scan_result=return_obj)

                if self._test_hello_done(rec):
                    break
                elif not read_more:
                    return_obj.handshake_failure = TlsHandshakeErrors.NO_TLS
                    return_obj.time_failed = time.time()
                    raise TlsHandshakeFailure('No TLS termination', scan_result=return_obj)

            except TlsIncomplete as e:
                logger.debug(e)
                if not read_more:
                    raise

            except TlsHandshakeAbort:
                raise

            except TlsHandshakeFailure:
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

    def _get_failure(self, packet):
        """
        Alert record if SSL failure has been detected - fatal error
        :param packet: 
        :return:
        :rtype: TLSAlert
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
                return alert

        return None

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

        ispy3 = util.is_py3()
        for srec in packet.records:
            if srec.content_type != TLSContentType.HANDSHAKE:
                continue

            handshakes = [srec.payload]
            if ispy3 and isinstance(srec.payload, TLSHandshakes):
                handshakes = list(srec.payload.handshakes)

            for handshake in handshakes:
                if not isinstance(handshake, TLSHandshake):
                    raise TlsIncomplete('Handshake declared but no handshake found (hello)')

                cur_payload = handshake
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

        ispy3 = util.is_py3()
        certificates = []
        for srec in packet.records:
            if srec.content_type != TLSContentType.HANDSHAKE:
                continue

            handshakes = [srec.payload]
            if ispy3 and isinstance(srec.payload, TLSHandshakes):
                handshakes = list(srec.payload.handshakes)

            for handshake in handshakes:
                if not isinstance(handshake, TLSHandshake):
                    raise TlsIncomplete('Handshake declared but no handshake found (cert)')

                cur_payload = handshake
                while self._search_payload(cur_payload):
                    if isinstance(cur_payload, TLSHandshake) and cur_payload.type == TLSHandshakeType.CERTIFICATE:
                        cert_list_rec = cur_payload.payload
                        certificates_rec = cert_list_rec.certificates
                        certificates += [bytes(x.data) for x in certificates_rec]
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
                        return b''.join(total_data)
                else:
                    # sleep for sometime to indicate a gap
                    time.sleep(0.1)
            except:
                pass

        # join all parts to make final string
        return b''.join(total_data)


def handshake_main():
    """
    Main handshake scan routine when invoked as a separate script
    :return:
    """
    import argparse
    coloredlogs.install(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description='TLS handshake test')

    parser.add_argument('--sni', dest='sni', default=None,
                        help='SNI name - use if host is specified by IP')

    parser.add_argument('--tls-ver', dest='tls_ver', default='TLS_1_2',
                        help='TLS version')

    parser.add_argument('--rsa', dest='rsa', default=False, action='store_const', const=True,
                        help='RSA certs only')

    parser.add_argument('--ecc', dest='ecc', default=False, action='store_const', const=True,
                        help='ECC certs only')

    parser.add_argument('hosts', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='host to connect to')

    args = parser.parse_args()
    if len(args.hosts) == 0:
        parser.print_usage()
        return

    for host in args.hosts:
        handshake_main_host(host, args)


def handshake_main_host(host, args):
    """
    One host scan
    :param host:
    :param args:
    :return:
    """
    port = 443
    target = host
    if ':' in target:
        target, port = target.split(':', 1)
        port = int(port)

    tester = TlsHandshaker()
    tester.timeout = 3
    tester.attempts = 3
    tester.tls_version = args.tls_ver
    sni = args.sni if args.sni else target
    ecc = None
    if args.ecc:
        ecc = True
    elif args.rsa:
        ecc = False

    logger.info('Testing %s:%s' % (target, port))
    ret = tester.try_handshake(host=target, port=port, domain=sni, ecc=ecc)

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


if __name__ == '__main__':
    handshake_main()




