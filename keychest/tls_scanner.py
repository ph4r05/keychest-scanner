#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Server part of the script
"""

from daemon import Daemon
from core import Core
from config import Config
from dbutil import MySQL, ScanJob, Certificate, CertificateAltName, DbCrtShQuery, DbCrtShQueryResult, \
    DbHandshakeScanJob, DbHandshakeScanJobResult

from trace_logger import Tracelogger
from tls_handshake import TlsHandshaker, TlsHandshakeResult, TlsIncomplete, TlsTimeout, TlsException
from cert_path_validator import PathValidator, ValidationException
from tls_domain_tools import TlsDomainTools

import logging
import requests
import sqlalchemy as salch


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class TlsScanResult(object):
    """
    Scanner result obj
    """
    def __init__(self):
        self.tls_res = None  # Tls handshake result


class TlsScanner(object):
    """
    Extended TLS scanner for Keychest
    handshake scan + request GET on the https handshake to verify availability.
    if problem -> http GET, follow redirect.
    """

    def __init__(self):
        self.trace_logger = Tracelogger(logger)
        self.tls_handshaker = TlsHandshaker(timeout=5, tls_version='TLS_1_2', attempts=3)
        self.crt_validator = PathValidator()
        self.domain_tools = TlsDomainTools()

    def scan(self, domain, port=443):
        """
        TODO: implement
        :param domain: 
        :param port: 
        :return: 
        """

    def _wrap_requests(self, fnc):
        """
        Calls fnc in try-catch for requests error
        :param fnc: 
        :return: fnc (result, err)
        """
        error = None
        try:
            res = fnc()
            return res, None

        except requests.exceptions.ReadTimeout as rte:
            error = 'READ_TO'
            self.trace_logger.log(rte)

        except requests.exceptions.ConnectTimeout as cte:
            error = 'CONN_TO'
            self.trace_logger.log(cte)

        except requests.exceptions.SSLError as cte:
            error = 'SSL_ERR'
            self.trace_logger.log(cte)

        except requests.exceptions.ConnectionError as ce:
            error = 'CONN_FAIL'
            logger.debug('Connection error: %s' % ce)
            self.trace_logger.log(ce)

        except requests.exceptions.RequestException as re:
            error = 'GEN_ERR'
            logger.debug('Connection error: %s' % re)
            self.trace_logger.log(re)

        except IOError as ioe:
            error = 'IO_ERR'
            logger.debug('IO error: %s' % ioe)
            self.trace_logger.log(ioe)

        return None, error

    def load_redirect(self, url, **kwargs):
        """
        Loads redirect - tries to connect on the given URL to load redirect.
        :param url: 
        :return: (new_url, error)
        """
        def fnc():
            return self.domain_tools.follow_domain_redirect(url, **kwargs)

        return self._wrap_requests(fnc)

    def req_connect(self, url, **kwargs):
        """
        requests connect
        :param url: 
        :param kwargs: 
        :return: result, error
        """
        def fnc():
            return requests.get(url, **kwargs)

        return self._wrap_requests(fnc)

    def err2status(self, err):
        """
        Err to status in DB
        :param err:
        :return:
        """
        if err is None:
            return 'OK'
        return err

