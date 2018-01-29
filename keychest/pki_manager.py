#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PKI, certificate managers and processors
"""
import collections

from past.builtins import basestring  # pip install future
from past.builtins import cmp
from future.utils import iteritems

import logging
import threading

from . import util, util_cert
from .errors import Error
from .trace_logger import Tracelogger


logger = logging.getLogger(__name__)


#
# Exceptions
#

class PkiOperationAlreadyInProgress(Error):
    """PKI does not support multiple operations of this kind, backoff"""
    def __init__(self, message=None, cause=None, **kwargs):
        super(PkiOperationAlreadyInProgress, self).__init__(message=message, cause=cause)


class PkiRenewalFailed(Error):
    """PKI Certificate renewal failed"""
    def __init__(self, message=None, cause=None, **kwargs):
        super(PkiRenewalFailed, self).__init__(message=message, cause=cause)
        self.fail_data = kwargs.get('fail_data')


class PkiCouldNotReadCertError(Error):
    """PKI Certificate renewal failed"""
    def __init__(self, message=None, cause=None, **kwargs):
        super(PkiCouldNotReadCertError, self).__init__(message=message, cause=cause)


class PkiAuthCheckFailed(Error):
    """Authorization configuration for the renewal failed"""
    def __init__(self, message=None, cause=None, **kwargs):
        super(PkiAuthCheckFailed, self).__init__(message=message, cause=cause)


class PkiAuthCheckFailedRequest(PkiAuthCheckFailed):
    """Authorization configuration for the renewal failed - request error"""
    def __init__(self, message=None, cause=None, **kwargs):
        super(PkiAuthCheckFailedRequest, self).__init__(message=message, cause=cause)


class PkiAuthCheckFailedInvalidChallenge(PkiAuthCheckFailed):
    """Authorization configuration for the renewal failed - invalid response challenge"""
    def __init__(self, message=None, cause=None, **kwargs):
        super(PkiAuthCheckFailedInvalidChallenge, self).__init__(message=message, cause=cause)


#
# Cert lifecycle wrappers
#


class CertRenewal(object):
    """
    Certificate renewal processing object
    """
    def __init__(self, manager=None, **kwargs):
        self.manager = manager  # type: PkiSubManager
        self.domains = []
        self.trace_logger = Tracelogger(logger)

        # State
        self.cert_changed = False
        self.cert_data = None
        self.priv_data = None
        self.chain_data = None

    def renew(self, **kwargs):
        """
        Performs the renewal
        :return:
        """
        raise ValueError('Not Implemented')


#
# PKI manager - base
#


class PkiSubManager(object):
    """
    PKI manager for particular CA
    """
    def __init__(self, pki_manager=None, **kwargs):
        self.pki_manager = pki_manager
        self.trace_logger = Tracelogger(logger)
        self.local_data = threading.local()

    @property
    def config(self):
        return self.pki_manager.config

    @property
    def db(self):
        return self.pki_manager.db

    def register(self, pki_manager=None, **kwargs):
        """
        Registers to the main manager
        :param pki_manager:
        :param kwargs:
        :return:
        """
        pki_manager = self.pki_manager if not pki_manager else pki_manager
        pki_manager.register_manager(self)

    def is_my_ca(self, obj):
        """
        Returns true if this CA belongs to this manager
        :param obj:
        :return:
        """
        return False

    def ca_type(self):
        """
        Returns CA type - string ID
        :return:
        """
        raise ValueError('Not implemented')

    def renew_cert(self, s, job=None):
        """
        Renew cert task
        :param s:
        :param job:
        :param domains:
        :param finish_task:
        :return:
        :rtype: CertRenewal
        """
        raise ValueError('Not implemented')

    def test_renew_config(self, domain, **kwargs):
        """
        Test if the renew is configured properly so renewal works
        :return:
        """
        kwargs.setdefault('attempts', 3)
        kwargs.setdefault('timeout', 10)


#
# General PKI manager, wrapper / resolver
#


class PkiManager(object):
    """
    Base PKI manager for certificate related tasks
    """

    def __init__(self):
        self.db = None
        self.config = None
        self.trace_logger = Tracelogger(logger)
        self.local_data = threading.local()
        self.managers = []  # type: list[PkiSubManager]

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
        if 'trace_logger' in kwargs:
            self.trace_logger = kwargs.get('trace_logger')

    def register_manager(self, manager):
        """
        Registers manager to the managers DB
        :param manager:
        :return:
        """
        self.managers.append(manager)

    def resolve_manager(self, obj):
        """
        Resolves managers from the list
        :param obj:
        :return:
        """
        for mgr in self.managers:
            if mgr.is_my_ca(obj):
                return mgr
        return None


