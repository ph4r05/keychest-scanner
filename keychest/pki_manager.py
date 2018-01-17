#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PKI, certificate managers and processors
"""

from past.builtins import basestring  # pip install future
from past.builtins import cmp
from future.utils import iteritems

import json
from cryptography.x509 import Certificate as X509Certificate

from . import util, util_cert
from .consts import CertSigAlg


class PkiManager(object):
    """
    Base PKI manager for certificate related tasks
    """

    def __init__(self):
        self.db = None
        self.config = None

    def init(self, **kwargs):
        """
        Initializes the PKI manager
        :param kwargs:
        :return:
        """
        if 'db' in kwargs:
            self.db = kwargs.get('db')
        if 'config' in kwargs:
            self.config = kwargs.get('config')

    def parse_certificate(self, cert_db, pem=None, der=None):
        """
        Parses the certificate, returns the parsed cert
        :param cert_db:
        :param pem:
        :param der:
        :return: (cryptography cert)
        :rtype: X509Certificate
        """
        cert = None  # type: X509Certificate
        if pem is not None:
            cert = util.load_x509_der(util.pem_to_der(str(cert_db.pem)))
        elif der is not None:
            cert = util.load_x509_der(der)
        else:
            raise ValueError('No certificate provided')

        alt_names = [util.utf8ize(x) for x in util.try_get_san(cert)]

        cert_db.cname = util.utf8ize(util.try_get_cname(cert))
        cert_db.fprint_sha1 = util.lower(util.try_get_fprint_sha1(cert))
        cert_db.fprint_sha256 = util.lower(util.try_get_fprint_sha256(cert))
        cert_db.valid_from = util.dt_norm(cert.not_valid_before)
        cert_db.valid_to = util.dt_norm(cert.not_valid_after)
        cert_db.subject = util.utf8ize(util.get_dn_string(cert.subject))
        cert_db.issuer = util.utf8ize(util.get_dn_string(cert.issuer))
        cert_db.is_ca = util.try_is_ca(cert)
        cert_db.is_precert = util.try_is_precert(cert)
        cert_db.is_precert_ca = util.try_is_precert_ca(cert)
        cert_db.is_self_signed = util.try_is_self_signed(cert)
        cert_db.is_le = 'Let\'s Encrypt' in cert_db.issuer

        cert_db.sig_alg = CertSigAlg.oid_to_const(cert.signature_algorithm_oid)
        cert_db.key_type = util_cert.try_get_key_type(cert.public_key())
        cert_db.key_bit_size = util_cert.try_get_pubkey_size(cert.public_key())

        cert_db.subject_key_info = util.take(util.lower(util.b16encode(
            util.try_get_subject_key_identifier(cert))), 64)
        cert_db.authority_key_info = util.take(util.lower(util.b16encode(
            util.try_get_authority_key_identifier(cert))), 64)

        cert_db.is_ev = util_cert.try_cert_is_ev(cert)
        cert_db.is_ov = not util.is_empty(util.try_get_org_name(cert))
        cert_db.is_cn_wildcard = util_cert.is_cname_wildcard(cert_db.cname)
        cert_db.is_alt_wildcard = util_cert.num_wildcard_alts(alt_names) > 0
        cert_db.issuer_o = util.take(util.utf8ize(util.try_get_issuer_org(cert)), 64)

        alt_name_test = list(alt_names)
        if not util.is_empty(cert_db.cname):
            alt_name_test.append(cert_db.cname)

        cert_db.is_cloudflare = len(util_cert.cloudflare_altnames(alt_name_test)) > 0
        cert_db.alt_names_arr = alt_names
        cert_db.alt_names = json.dumps(alt_names)
        cert_db.alt_names_cnt = len(alt_names)

        return cert
