#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
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


class ValidationResult(object):
    """
    Cert path validation result
    """
    def __init__(self):
        self.valid = False
        self.ca_validation = None  # type: SubValidationResult
        self.leaf_validation = None  # type: SubValidationResult

        # Cryptography loaded certificates
        self.ca_certs = []
        self.leaf_certs = []
        self.valid_leaf_certs = []

    def __repr__(self):
        return '<ValidationResult(valid=%r, ca_validation=%r, leaf_validation=%r, ca_certs=%r,' \
               'leaf_certs=%r, valid_leaf_certs=%r)>' \
               % (self.valid, self.ca_validation, self.leaf_validation, self.ca_certs,
                  self.leaf_certs, self.valid_leaf_certs)


class SubValidationResult(object):
    """
    Validation results for one single chain processing with one method.
    Separate instance for intermediate verification, separate for leaf cert verification.
    """
    def __init__(self):
        self.certs_valid = 0
        self.fprints = []            # sequence of fingerprints
        self.fprints_valid = []      # sequence of valid certs sha256 fingerprints
        self.validation_order = []   # sequence of validated cert ids in chain in validation
        self.validation_steps = 0    # number of validation steps of the algorithm
        self.validation_errors = {}  # idx -> validation error

    def __repr__(self):
        return '<SubValidationResult(certs_valid=%r, fprints_cnt=%r, fprints_valid=%r, validation_order=%r, ' \
               'validation_steps=%r, validation_errors=%r)>' \
               % (self.certs_valid, len(self.fprints), self.fprints_valid, self.validation_order, self.validation_steps,
                  self.validation_errors)


class ValidationOsslContext(object):
    """
    Context needed for OSSL path validation
    """
    def __init__(self):
        self.verified_fprints = set()
        self.verified_certs = []

    def __repr__(self):
        return '<ValidationOsslContext(verified_fprints=%r)>' % self.verified_fprints


class ValidationException(errors.Error):
    """General exception"""
    def __init__(self, message=None, cause=None, result=None, **kwargs):
        super(ValidationException, self).__init__(message=message, cause=cause)
        self.result = result
        self.error_code = None
        self.error_depth = None
        self.error_msg = None
        self.error_cert = None


class ValidationOsslException(ValidationException):
    """OSSL exception - error codes"""
    def __init__(self, message=None, cause=None, result=None, **kwargs):
        super(ValidationOsslException, self).__init__(message=message, cause=cause, result=result)
        self.error_code = None
        self.error_depth = None
        self.error_msg = None
        self.error_cert = None


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

        aux_roots = self._try_open_aux_roots()
        if aux_roots is not None:
            roots += aux_roots

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

    def _try_open_aux_roots(self):
        """
        Tries to open aux trust roots
        :return:
        """
        trust_aux = os.environ.get('KC_TRUST_ROOTS_AUX')
        if trust_aux is None:
            return None

        try:
            with open(trust_aux, 'rb') as fh:
                return fh.read()
        except Exception as e:
            logger.error('Could not open AUX CA trust roots: %s : %s ' % (trust_aux, e))
        return None

    def _new_ossl_store(self):
        """
        Creates a new root store for cert verification
        :return: 
        """
        cur_store = X509Store()
        for crt in self.root_certs:
            cur_store.add_cert(crt)
        return cur_store

    def _load_chain(self, chain, is_der=False):
        """
        Parses certificates from the chain by cryptography and openssl
        :param chain:
        :param is_der:
        :return: [(ossl, crypt), ...]
        """
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
        return chain_loaded

    def validate(self, chain, is_der=False):
        """
        Chain of certificates, incremental validation
        :param chain: 
        :return:
        :rtype: ValidationResult
        """
        result = ValidationResult()
        if not isinstance(chain, list):
            chain = [chain]

        # parse chain certs to [(ossl certificate, cryptography certificate), ...]
        chain_loaded = self._load_chain(chain, is_der)

        # Sort certs to CA and non-CA certificates
        for idx, rec in enumerate(chain_loaded):
            if util.try_is_ca(rec[1]):
                result.ca_certs.append(rec[1])
            else:
                result.leaf_certs.append(rec[1])

        if len(result.leaf_certs) == 0:
            raise ValidationException('No leaf certificate', result=result)

        # Incremental verification of certificates in the cert chain.
        # Currently only OSSL validation is supported.
        validation_ctx = ValidationOsslContext()

        # Stage 1 - verify all intermediate CAs, allow certificate fails
        interm_res = self._verify_certs(chain_loaded, validation_ctx=validation_ctx, interm_mode=True)
        result.ca_validation = interm_res

        # Stage 2 - verify all leaf certs
        leaf_res = self._verify_certs(chain_loaded, validation_ctx=validation_ctx, interm_mode=False)
        result.leaf_validation = leaf_res
        result.valid = leaf_res.certs_valid > 0

        for idx in leaf_res.validation_order:
            result.valid_leaf_certs.append(chain_loaded[idx][1])

        return result

    def _verify_certs(self, chain_loaded, validation_ctx, interm_mode=True):
        """
        Verify certificates in an arbitrary order in the chain.
        :param chain_loaded:
        :param validation_ctx:
        :param interm_mode: intermediate mode
        :return:
        """
        result = SubValidationResult()
        idx_already_valid = set()

        # Iterate on chain certificates until there is some progress
        while True:
            # In each step try to validate at least one certificate
            certificates_validated = 0

            # try to validate each certificate. At least one should be valid now.
            for idx in range(0, len(chain_loaded)):
                if idx in idx_already_valid:
                    continue

                to_verify = chain_loaded[idx]
                is_ca_crt = util.try_is_ca(to_verify[1])
                fprint = util.try_get_fprint_sha256(to_verify[1])

                # in the intermediate mode require only CA certs
                if interm_mode != is_ca_crt:
                    continue

                if fprint not in result.fprints:
                    result.fprints.append(fprint)

                try:
                    # Validate certificate with the validation method corresponding to the ctx.
                    self._validate_cert(to_verify=to_verify, fprint=fprint, context=validation_ctx,
                                        interm_mode=interm_mode)

                    # Validation passed - update stats
                    result.certs_valid += 1
                    certificates_validated += 1
                    idx_already_valid.add(idx)

                    result.validation_order.append(idx)
                    result.fprints_valid.append(fprint)
                    result.validation_errors[idx] = None

                except ValidationOsslException as vex:
                    vex.result = result
                    result.validation_errors[idx] = vex

                except ValidationException as vex:
                    vex.result = result
                    result.validation_errors[idx] = vex

                except Exception as e:
                    self.trace_logger.log(e, custom_msg='General Exc in cert validation')
                    result.validation_errors[idx] = e

            # Terminal condition - no more progress
            if certificates_validated == 0:
                break

            result.validation_steps += 1

        return result

    def _validate_cert(self, to_verify, fprint, context, interm_mode):
        """
        Validates current certificate in the given context.
        Extension - different context for different validation method.
        :param to_verify:
        :param context:
        :return:
        """
        try:
            # current trust store with previously validated intermediate certificates
            cur_store = self._new_ossl_store()
            for crt in context.verified_certs:
                cur_store.add_cert(crt[0])

            # OSSL Verification w.r.t. base store
            store_ctx = X509StoreContext(cur_store, to_verify[0])
            store_ctx.verify_certificate()

            # Add valid intermediate to the verified registers
            if interm_mode and fprint not in self.root_fprints and fprint not in context.verified_fprints:
                context.verified_certs.append(to_verify)
                context.verified_fprints.add(fprint)

        except X509StoreContextError as cex:  # translate specific exception to our general exception
            self.trace_logger.log(cex, custom_msg='Exc in path validation, interm: %s. ' % interm_mode)

            # message - error, depth, message, certificate which caused an error
            ex = ValidationOsslException('Validation failed', cause=cex)
            try:
                ex.error_code = cex.message[0]
                ex.error_depth = cex.message[1]
                ex.error_msg = cex.message[2]
                ex.error_cert = cex.certificate
            except:
                pass

            raise ex

