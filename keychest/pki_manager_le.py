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
import threading

from cryptography.x509 import Certificate as X509Certificate

from . import util, util_cert
from .certificate_manager import CertificateManager
from .dbutil import DbPkiIssuer, DbManagedCertificate, DbManagedPrivate, DbManagedCertChain, DbHelper
from .errors import Error
from .letsencrypt import LetsEncrypt
from .semaphore_manager import SemaphoreManager
from .server_management import ManagementModule
from .stat_sem import SemaphoreWrapper
from .trace_logger import Tracelogger


logger = logging.getLogger(__name__)


#
# Exceptions
#

class PkiOperationAlreadyInProgress(Error):
    """PKI does not support multiple operations of this kind, backoff"""
    def __init__(self, message=None, cause=None):
        super(PkiOperationAlreadyInProgress, self).__init__(message=message, cause=cause)





#
# Cert lifecycle wrappers
#


class CertRenewal(object):
    """
    Certificate renewal processing object
    """
    def __init__(self, **kwargs):
        """
        pass
        """


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

    def renew_cert(self, s, job=None, finish_task=None):
        """
        Renew cert task
        :param s:
        :param job:
        :param domains:
        :param finish_task:
        :return:
        """
        raise ValueError('Not implemented')


#
# PKI managers - CAs
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
        le.staging = True  # TODO: remove staging in production
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

    def get_certbot_sem_key(self):
        """
        Semaphore certbot key
        :return:
        """
        return 'renew-certbot'

    def renew_cert(self, s, job=None, finish_task=None):
        """
        Renew certificate job for management.
        :param s:
        :param job:
        :param finish_task:
        :return:
        """

        # Extract main domain name from the service configuration
        domains = ManagementModule.get_service_domains(job.target)

        # Perform proxied domain validation with certbot, attempt renew / issue.
        # CA-related renewal for now. Later extend to renewal object, separate CA dependent code.
        sem_key = self.get_certbot_sem_key()
        sem = self.semaphore_manager.get(sem_key, count=1)
        sem_wrap = SemaphoreWrapper(sem, blocking=0, timeout=0)

        with sem_wrap:
            if not sem_wrap.acquired:
                raise PkiOperationAlreadyInProgress()

            return self.renew_cert_body(s=s, job=job, domains=domains, finish_task=finish_task)

    def renew_cert_body(self, s, job=None, domains=None, finish_task=None):
        """
        Pass
        :param s:
        :param job:
        :param domains:
        :param finish_task:
        :return:
        """
        req_data = collections.OrderedDict()
        req_data['CA'] = job.target.svc_ca.id
        req_data['CA_type'] = 'LE'
        req_data['domains'] = domains
        renew_record = self.create_renew_record(job, req_data=req_data)

        le_ins = self.get_thread_le()
        ret, out, err = le_ins.certonly(email='le@keychest.net', domains=domains, auto_webroot=True)
        if ret != 0:
            logger.warning('Certbot failed with error code: %s, err: %s' % (ret, err))
            renew_record.last_issue_status = -2
            renew_record.last_issue_data = json.dumps({'ret': ret, 'out': out, 'err': err})
            s.add(renew_record)
            finish_task(last_check_status=-2)
            self.events.on_renew_cerbot_fail(job, (ret, out, err))
            return

        # if certificate has changed, load certificate file to the database, update, signalize,...
        if not le_ins.cert_changed:
            logger.debug('Certificate did not change for mgmt cert: %s, domain: %s' % (job.target.id, domains[0]))
            renew_record.last_issue_status = 2
            s.add(renew_record)
            finish_task(last_check_status=2)
            return

        domain = domains[0]
        priv_file, cert_file, ca_file = le_ins.get_cert_paths(domain=domain)
        pki_files = []

        # Load given files to memory
        for fname in [priv_file, cert_file, ca_file]:
            with open(fname, 'r') as fh:
                pki_files.append(fh.read())

        # Load the full cert chain, with the newest issued cert in the first entry
        chain_arr = CertificateManager.pem_chain_to_array(pki_files[2])
        res = self.cert_manager.process_full_chain(s, cert_chain=chain_arr, is_der=False)

        all_certs = res[0]
        if len(all_certs) == 0:
            logger.warning('LE Chain is empty')
            return

        leaf_cert = all_certs[0]
        chain_certs = all_certs[1:]

        # All base model certificates are in the DB now
        # Check existence of the chaining records and private key records.
        privkey_hash = CertificateManager.get_privkey_hash(pem=pki_files[0])
        priv_db = s.query(DbManagedPrivate)\
            .filter(DbManagedPrivate.private_hash == privkey_hash)\
            .first()

        if priv_db is None:
            priv_db = DbManagedPrivate()
            priv_db.private_hash = privkey_hash
            priv_db.certificate_id = leaf_cert.id
            priv_db.private_data = self.encryptor.encrypt(util.to_string(pki_files[0]))
            priv_db.created_at = priv_db.updated_at = salch.func.now()
            s.add(priv_db)

        renew_record.new_certificate_id = leaf_cert.id
        new_leaf_cert = True
        new_managed_cert = None

        # Did managed cert change?
        if renew_record.certificate_id == leaf_cert.id:
            new_leaf_cert = False
            renew_record.last_issue_status = 3
            s.add(renew_record)

        else:
            # Deprecate current certificate from the job, create new managed cert entry.
            job.managed_certificate = s.merge(job.managed_certificate)
            job.managed_certificate.record_deprecated_at = salch.func.now()  # deprecate current record

            new_managed_cert = DbHelper.clone_model(s, job.managed_certificate, do_copy=False)  # type: DbManagedCertificate
            new_managed_cert.id = None
            new_managed_cert.certificate_id = leaf_cert.id
            new_managed_cert.deprecated_certificate_id = job.certificate.id if job.certificate else None
            new_managed_cert.record_deprecated_at = None
            new_managed_cert.last_check_at = salch.func.now()
            new_managed_cert.last_check_status = 100
            new_managed_cert.created_at = new_managed_cert.updated_at = salch.func.now()
            s.add(new_managed_cert)

        # Chain process - clear the previous chains, set new ones
        stmt = salch.delete(DbManagedCertChain)\
            .where(DbManagedCertChain.certificate_id == leaf_cert.id)
        s.execute(stmt)

        for idx, cert in enumerate(chain_certs):
            cur_chain = DbManagedCertChain()
            cur_chain.order_num = idx
            cur_chain.certificate_id = leaf_cert.id
            cur_chain.chain_certificate_id = cert.id
            cur_chain.created_at = cur_chain.updated_at = salch.func.now()
            s.add(cur_chain)

        if not new_leaf_cert:
            finish_task(last_check_status=4)
            return

        # Cert issue record - store renewal happened
        renew_record.last_issue_status = 1
        renew_record.new_certificate_id = leaf_cert.id
        s.add(renew_record)

        # Signalize event - new certificate
        self.events.on_renewed_certificate(leaf_cert, job, new_managed_cert)

        # TODO: In the agent - signalize this event to the master, attach new certificate & privkey
        pass

        # Trigger tests - set last scan to null
        self.trigger_test_managed_tests(s, solution_id=job.solution.id, service_id=job.target.id)
        finish_task(last_check_status=0)


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


