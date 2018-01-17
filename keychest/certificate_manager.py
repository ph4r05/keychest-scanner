#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Certificate managers and processors
"""
from past.builtins import basestring  # pip install future
from past.builtins import cmp
from future.utils import iteritems

import base64
import json
import logging
import time

from cryptography.x509 import Certificate as X509Certificate
import sqlalchemy as salch

from . import util, util_cert
from .errors import Error
from .tls_domain_tools import TlsDomainTools
from .consts import CertSigAlg
from .dbutil import Certificate, CertificateAltName, DbHandshakeScanJobResult
from .database_manager import DatabaseManager
from .trace_logger import Tracelogger


logger = logging.getLogger(__name__)


class CertificateManager(object):
    """
    Base certificate manager for certificate related tasks
    """

    def __init__(self):
        self.db = None
        self.config = None
        self.db_manager = None  # type: DatabaseManager
        self.trace_logger = Tracelogger(logger)

    def init(self, **kwargs):
        """
        Initializes the certificate manager
        :param kwargs:
        :return:
        """
        if 'db' in kwargs:
            self.db = kwargs.get('db')
        if 'config' in kwargs:
            self.config = kwargs.get('config')
        if 'trace_logger' in kwargs:
            self.trace_logger = kwargs.get('trace_logger')
        if 'db_manager' in kwargs:
            self.db_manager = kwargs.get('db_manager')

    #
    # Base certificate processing
    #

    def parse_certificate(self, cert_db, pem=None, der=None, **kwargs):
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

    #
    # Certificate load / save
    #

    def cert_load_existing(self, s, certs_id):
        """
        Loads existing certificates with cert id from the set
        :param s:
        :param certs_id:
        :return:
        :rtype: dict[int -> int]
        """
        ret = {}

        int_list = [int(x) for x in certs_id]
        res = s.query(Certificate.id, Certificate.crt_sh_id).filter(Certificate.crt_sh_id.in_(int_list)).all()
        for cur in res:
            ret[int(cur.crt_sh_id)] = int(cur.id)

        return ret

    def cert_load_by_id(self, s, certs_id):
        """
        Loads certificates by IDs
        :param s:
        :param certs_id:
        :return:
        """
        was_array = True
        if not isinstance(certs_id, list):
            certs_id = [certs_id]
            was_array = False

        certs_id = [int(x) for x in util.compact(certs_id)]
        ret = {}

        res = s.query(Certificate) \
            .filter(Certificate.id.in_(list(certs_id))).all()

        for cur in res:
            if not was_array:
                return cur

            ret[cur.id] = cur

        return ret if was_array else None

    def cert_load_fprints(self, s, fprints):
        """
        Load certificate by sha1 fprint
        :param s:
        :param fprints:
        :return:
        :rtype: union[dict[string -> Certificate], Certificate]
        """
        was_array = True
        if not isinstance(fprints, list):
            fprints = [fprints]
            was_array = False

        fprints = util.lower(util.strip(fprints))
        ret = {}

        res = s.query(Certificate) \
            .filter(Certificate.fprint_sha1.in_(list(fprints))).all()

        for cur in res:
            if not was_array:
                return cur

            ret[util.lower(cur.fprint_sha1)] = cur

        return ret if was_array else None

    def add_cert_or_fetch(self, s=None, cert_db=None, fetch_first=False, add_alts=True):
        """
        Tries to insert new certificate to the DB.
        If fails due to constraint violation (somebody preempted), it tries to load
        certificate with the same fingerprint. If fails, repeats X times.
        Automatically commits the transaction before inserting - could fail under high load.
        :param s:
        :param cert_db:
        :type cert_db: Certificate
        :return:
        :rtype: tuple[Certificate, bool]
        """
        close_after_done = False
        if s is None:
            s = self.db.get_session()
            close_after_done = True

        def _close_s():
            if s is None:
                return
            if close_after_done:
                util.silent_close(s)

        for attempt in range(5):
            done = False
            if not fetch_first or attempt > 0:
                if not attempt == 0:  # insert first, then commit transaction before it may fail.
                    s.commit()
                try:
                    s.add(cert_db)
                    s.commit()
                    done = True

                    # Insert all alt names for the certificate
                    if add_alts and not util.is_empty(cert_db.alt_names_arr):
                        uniq_sorted_alt_names = util.stable_uniq(util.compact(cert_db.alt_names_arr))
                        for alt_name in uniq_sorted_alt_names:
                            c_alt = CertificateAltName()
                            c_alt.cert_id = cert_db.id
                            c_alt.alt_name = alt_name
                            c_alt.is_wildcard = TlsDomainTools.has_wildcard(alt_name)
                            s.add(c_alt)
                        s.commit()

                        # Live migration to domain database
                        for alt_name in uniq_sorted_alt_names:
                            if TlsDomainTools.has_wildcard(alt_name):
                                continue
                            self.db_manager.load_domain_name(s, domain_name=alt_name, pre_commit=False, fetch_first=True)
                        s.commit()

                except Exception as e:
                    self.trace_logger.log(e, custom_msg='Probably constraint violation')
                    s.rollback()

            cert_db.trans_is_new = 1
            if done:
                _close_s()
                return cert_db, 1

            cert = self.cert_load_fprints(s, cert_db.fprint_sha1)  # type: Certificate
            if cert is not None:
                _close_s()
                cert.trans_is_new = 0
                return cert, 0

            time.sleep(0.01)
        _close_s()
        raise Error('Could not store / load certificate')

    #
    # Cert processing
    #

    def process_certificate_file(self, s, cert_file, **kwargs):
        """
        Loads the file from the file, fetches or adds to the certificate database.
        :param s:
        :param cert_file:
        :return:
        :rtype: tuple[Certificate, bool]
        """
        cert_pem = None
        with open(cert_file) as fh:
            cert_pem = fh.read()
        return self.process_certificate(s, cert_pem,  **kwargs)

    def process_certificate(self, s, cert_pem, **kwargs):
        """
        Loads the file from the file, fetches or adds to the certificate database.
        :param s:
        :param cert_pem:
        :return:
        :rtype: tuple[Certificate, bool]
        """
        try:
            cert_db = Certificate()
            cert = self.parse_certificate(cert_db, pem=cert_pem)

            cert_existing = self.cert_load_fprints(s, [cert_db.fprint_sha1])
            if cert_existing:
                return cert_db, False

            cert_db.created_at = salch.func.now()
            cert_db.pem = util.strip_pem(cert_pem)
            cert_db.source = kwargs.get('source', 'renew')
            cert_db, is_new_cert = self.add_cert_or_fetch(s, cert_db, add_alts=True)
            return cert_db, is_new_cert

        except Exception as e:
            logger.error('Exception when processing a certificate %s' % (e,))
            self.trace_logger.log(e)
        return None, False

    def process_full_chain(self, s, cert_chain, is_der=True, **kwargs):
        """
        Processes full chain certificate list - add all to the database
        :param s: session
        :param cert_chain: tls scan response
        :type cert_chain: list[string]
        :param is_der:
        :return:
        :rtype: tuple[list[Certificate], list[string], int, int]
        """
        if util.is_empty(cert_chain):
            return

        # pre-parsing, get fprints for later load
        local_db = []
        fprints_handshake = set()
        for cert_obj in cert_chain:
            try:
                cert_db = Certificate()

                der = cert_obj if is_der else util.pem_to_der(util.to_string(str(cert_db.pem)))
                cert = self.parse_certificate(cert_db, der=der)

                local_db.append((cert_db, cert, cert_db.alt_names_arr, der))
                fprints_handshake.add(cert_db.fprint_sha1)

            except Exception as e:
                logger.error('Exception when processing a certificate %s' % (e,))
                self.trace_logger.log(e)

        # load existing certificates by fingerprints
        cert_existing = self.cert_load_fprints(s, list(fprints_handshake))
        leaf_cert_id = None
        all_cert_ids = set()
        num_new_results = 0
        prev_id = None
        all_certs = []

        # store non-existing certificates from the chain to the database
        for endb in reversed(local_db):
            cert_db, cert, alt_names, der = endb
            fprint = cert_db.fprint_sha1

            try:
                cert_db.created_at = salch.func.now()
                cert_db.pem = base64.b64encode(der)
                cert_db.source = kwargs.get('source', 'handshake')

                # new certificate - add
                # lockfree - add, if exception on add, try fetch, then again add,
                if fprint not in cert_existing:
                    cert_db, is_new_cert = self.add_cert_or_fetch(s, cert_db, add_alts=True)  # type: tuple[Certificate, bool]
                    if is_new_cert:
                        num_new_results += 1
                else:
                    cert_db = cert_existing[fprint]

                if cert_db.parent_id is None:
                    cert_db.parent_id = prev_id

                all_cert_ids.add(cert_db.id)

                if not cert_db.is_ca:
                    leaf_cert_id = cert_db.id

                prev_id = cert_db.id
                all_certs.append(cert_db)

            except Exception as e:
                logger.error('Exception when processing a handshake certificate %s' % (e,))
                self.trace_logger.log(e)

        all_certs = list(reversed(all_certs))
        return all_certs, cert_existing.keys(), leaf_cert_id, num_new_results

