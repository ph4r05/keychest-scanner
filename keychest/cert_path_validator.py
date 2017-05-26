#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import time
import requests
import util
import datetime
import traceback
import errors
import types
from trace_logger import Tracelogger


from OpenSSL.crypto import load_certificate, load_privatekey, FILETYPE_PEM, FILETYPE_ASN1, X509StoreContextError
from OpenSSL.crypto import X509Store, X509StoreContext


logger = logging.getLogger(__name__)


class ValidationException(errors.Error):
    """General exception"""
    def __init__(self, message=None, cause=None):
        super(ValidationException, self).__init__(message=message, cause=cause)


class PathValidator(object):
    """
    Validates trust path for certificates
    """
    def __init__(self):
        self.roots = None
        self.root_store = X509Store()
        self.root_certs = []
        self.root_fprints = set()  # sha256 root fingerprints

        self.trace_logger = Tracelogger(logger)

    def init(self):
        """
        Loads roots
        :return: 
        """
        roots = util.load_roots()
        roots_loaded = 0
        logger.debug('Trust Roots loaded')

        # 1 - load all CAs, roots from Mozilla.
        roots = roots.split('-----END CERTIFICATE-----')
        for root in roots:
            if len(root.strip()) == 0:
                continue
            try:
                root += '-----END CERTIFICATE-----'
                root_cert = load_certificate(FILETYPE_PEM, root)
                root_crypto_cert = util.load_x509(root)
                self.root_store.add_cert(root_cert)
                self.root_certs.append(root_cert)
                self.root_fprints.add(util.try_get_fprint_sha256(root_crypto_cert))
                roots_loaded += 1

            except Exception as e:
                logger.error('Exception in processing root cert %s' % e)
                self.trace_logger.log(e)

        logger.debug('Loaded %s trusted roots' % roots_loaded)

    def new_store(self):
        """
        Creates a new root store for cert verification
        :return: 
        """
        cur_store = X509Store()
        for crt in self.root_certs:
            cur_store.add_cert(crt)
        return cur_store

    def validate(self, chain, is_der=False):
        """
        Chain of certificates, incremental validation
        :param chain: 
        :return: 
        """
        if not isinstance(chain, types.ListType):
            chain = [chain]

        # load given certs
        chain_loaded = []
        for crt in chain:
            if is_der:
                crt_ossl = load_certificate(FILETYPE_ASN1, crt)
                crt_cryp = util.load_x509_der(crt)
                chain_loaded.append((crt_ossl, crt_cryp))
            else:
                crt_ossl = load_certificate(FILETYPE_PEM, crt)
                crt_cryp = util.load_x509(crt)
                chain_loaded.append((crt_ossl, crt_cryp))

        # Sort certs to CA and non-CA certificates
        leaf_is_first = False
        leaf_cert = None
        for idx, rec in enumerate(chain_loaded):
            if util.try_is_ca(rec[1]):
                pass
            elif leaf_cert is not None:
                raise ValidationException('Too many nonCA certificates')
            else:
                leaf_cert = rec
                leaf_is_first = idx == 0

        if leaf_cert is None:
            raise ValidationException('No leaf certificate')

        # Incremental verification of certificates in the cert chain
        if leaf_is_first:
            chain_loaded = list(reversed(chain_loaded))

        verified_fprints = set()
        verified_certs = []
        while len(chain_loaded) > 0:
            try:
                cur_store = self.new_store()
                for crt in verified_certs:
                    cur_store.add_cert(crt[0])

                to_verify = chain_loaded[0]
                chain_loaded = chain_loaded[1:]

                store_ctx = X509StoreContext(cur_store, to_verify[0])

                store_ctx.verify_certificate()

                fprint = util.try_get_fprint_sha256(to_verify[1])
                if fprint not in self.root_fprints and fprint not in verified_fprints:
                    verified_certs.append(to_verify)
                    verified_fprints.add(fprint)

            except X509StoreContextError as cex:
                self.trace_logger.log(cex, custom_msg='Exc in path validation')
                raise ValidationException('Validation failed', cause=cex)

            except Exception as e:
                self.trace_logger.log(e, custom_msg='General Exc in verification')
                raise ValidationException('Validation failed - generic fail', cause=e)

        return True

