#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PKI, certificate managers and processors
"""
import collections

from past.builtins import basestring  # pip install future
from past.builtins import cmp
from future.utils import iteritems

import datetime
import json
import logging
import os
import time
import threading

from cryptography.x509 import Certificate as X509Certificate
from requests import RequestException

from . import util, util_cert
from .certificate_manager import CertificateManager
from .dbutil import DbPkiIssuer, DbManagedCertificate, DbManagedPrivate, DbManagedCertChain, DbHelper
from .errors import Error
from .letsencrypt import LetsEncrypt
from .pki_manager import PkiOperationAlreadyInProgress, PkiRenewalFailed, PkiCouldNotReadCertError, PkiAuthCheckFailed,\
    PkiAuthCheckFailedRequest, PkiAuthCheckFailedInvalidChallenge, \
    CertRenewal, PkiSubManager, PkiManager

from .semaphore_manager import SemaphoreManager
from .server_management import ManagementModule
from .stat_sem import SemaphoreWrapper
from .trace_logger import Tracelogger


logger = logging.getLogger(__name__)


#
# Cert lifecycle wrappers
#


class CertRenewalLe(CertRenewal):
    """
    Certificate renewal processing object
    """
    def __init__(self, manager=None, **kwargs):
        super(CertRenewalLe, self).__init__(manager, **kwargs)

        self.s = kwargs.get('s')
        self.job = kwargs.get('job')
        self.finish_task = kwargs.get('finish_task')

        self.renew_result = 0
        self.renew_outs = (None, None)

    def renew(self, **kwargs):
        """
        Renewal
        :return:
        """
        # Perform proxied domain validation with certbot, attempt renew / issue.
        # CA-related renewal for now. Later extend to renewal object, separate CA dependent code.
        sem_key = self.manager.get_certbot_sem_key()
        sem = self.manager.semaphore_manager.get(sem_key, count=1)
        sem_wrap = SemaphoreWrapper(sem, blocking=0, timeout=0)

        with sem_wrap:
            if not sem_wrap.acquired:
                raise PkiOperationAlreadyInProgress()

            return self.renew_cert_body(**kwargs)

    def renew_cert_body(self, **kwargs):
        """
        Pass
        :param s:
        :param job:
        :param domains:
        :param finish_task:
        :return:
        """
        le_ins = self.manager.get_thread_le()

        ret, out, err = le_ins.certonly(email='le@keychest.net', domains=self.domains, auto_webroot=True)

        self.renew_result = ret
        self.renew_outs = out, err
        self.cert_changed = le_ins.cert_changed

        if ret != 0:
            raise PkiRenewalFailed('Certbot failed with error code: %s, err: %s' % (ret, err),
                                   fail_data={'ret': ret, 'out': out, 'err': err})

        domain = self.domains[0]
        self.read_cert_files(le_ins, domain)
        return True

    def read_cert_files(self, le_ins, domain):
        """
        Read renewed certificate files
        :return:
        """
        priv_file, cert_file, chain_file = le_ins.get_cert_paths(domain=domain)
        pki_files = []

        # Load given files to memory
        try:
            for fname in [cert_file, priv_file, chain_file]:
                with open(fname, 'r') as fh:
                    pki_files.append(fh.read())

            self.cert_data = pki_files[0]
            self.priv_data = pki_files[1]
            self.chain_data = pki_files[2]

        except Exception as e:
            logger.warning('Exception when reading cert files for domain %s: %s' % (domain, e))
            self.trace_logger.log(e)

            raise PkiCouldNotReadCertError()


#
# PKI manager
#


class PkiLeManager(PkiSubManager):
    """
    LetsEncrypt PKI manager
    """
    def __init__(self, pki_manager=None, **kwargs):
        super(PkiLeManager, self).__init__(pki_manager, **kwargs)
        self.trace_logger = Tracelogger(logger)
        self.semaphore_manager = SemaphoreManager()

    def new_le(self):
        """
        Constructs new LE
        :return:
        """
        le = LetsEncrypt(config=self.config,
                         config_dir=os.path.join(self.config.certbot_base, 'conf'),
                         work_dir=os.path.join(self.config.certbot_base, 'work'),
                         log_dir=os.path.join(self.config.certbot_base, 'log'),
                         webroot_dir=self.config.certbot_webroot
                         )
        le.staging = self.config.certbot_staging
        return le

    def get_thread_le(self):
        """
        Thread local LE
        :return:
        :rtype: LetsEncrypt
        """
        if not hasattr(self.local_data, 'le') or self.local_data.le is None:
            self.local_data.le = self.new_le()
        return self.local_data.le

    def is_my_ca(self, obj):
        """
        Returns true if this CA belongs to this manager
        :param obj:
        :return:
        """
        pki = obj
        if isinstance(obj, DbPkiIssuer):
            pki = obj.pki_type
        return pki == 'LE'

    def ca_type(self):
        """
        Current type ID
        :return:
        """
        return 'LE'

    def renew_cert(self, s, job=None):
        """
        Renew certificate job for management.
        :param s:
        :param job:
        :param finish_task:
        :return:
        """

        # Extract main domain name from the service configuration
        domains = ManagementModule.get_service_domains(job.target)

        ren = CertRenewalLe(self)
        ren.domains = domains
        return ren

    def test_renew_config(self, domain, **kwargs):
        """
        Test if the renew is configured properly so renewal works
        :return:
        """
        super(PkiLeManager, self).test_renew_config(domain, **kwargs)

        job = kwargs.get('job')
        attempts = kwargs.get('attempts')
        timeout = kwargs.get('timeout')
        host_addr = kwargs.get('host_addr')

        chal_path = None
        ins_le = self.get_thread_le()

        try:
            # Place random challenge to the webroot and check the contents
            webroot = ins_le.get_auto_webroot(domain)
            well_known = os.path.join(webroot, '.well-known')
            fname = 'chal_%s.txt' % util.random_alphanum(14)
            chal_fh, chal_path = util.unique_file(os.path.join(well_known, fname), mode=0o644)
            chal_data = util.random_alphanum(32)
            chal_fh.write(chal_data)
            chal_fh.close()
            chal_dir, chal_fname = os.path.split(chal_path)

            host_addr = domain if not host_addr else host_addr
            headers = {} if not host_addr else {'Host': domain}

            url_check = 'http://%s/.well-known/%s' % (host_addr, chal_fname)  # port 80 for webroot verification
            logger.debug('Going to check svc %s domain %s url %s' % (job.service.id, domain, url_check))

            time_start = time.time()
            resp = util.try_request_get(url_check, attempts=attempts, timeout=timeout, headers=headers)
            url_data = util.strip(resp.content)

            if url_data == chal_data:
                return {'status': '0', 'time': time.time() - time_start}
            else:
                raise PkiAuthCheckFailedInvalidChallenge()

        except RequestException as re:
            logger.error('RequestException on Svc check %s, domain: %s' % (re, domain), exc_info=re)
            raise PkiAuthCheckFailedRequest(cause=re)

        except Exception as e:
            logger.error('Exception on Svc check %s, domain: %s' % (e, domain), exc_info=e)
            raise PkiAuthCheckFailed(cause=e)

        finally:
            util.try_delete_file(chal_path)

    def get_certbot_sem_key(self):
        """
        Semaphore certbot key
        :return:
        """
        return 'renew-certbot'

