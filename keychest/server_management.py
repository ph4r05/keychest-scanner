#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key management scanning, renewal
"""

from past.builtins import basestring    # pip install future
from past.builtins import cmp
from future.utils import iteritems

from . import util
from .letsencrypt import LetsEncrypt
from .config import Config
from .redis_queue import RedisQueue
from .trace_logger import Tracelogger
from .errors import Error, InvalidHostname, ServerShuttingDown, InvalidInputData
from .server_jobs import JobTypes, BaseJob, PeriodicJob, PeriodicMgmtTestJob, ScanResults, PeriodicMgmtRenewalJob, \
    PeriodicMgmtHostCheckJob, PeriodicMgmtServiceCheckJob

from .server_module import ServerModule
from .audit import AuditManager
from .ebsysconfig import SysConfig
from .ansible_wrap import AnsibleWrapper
from .pki_manager import PkiManager, PkiOperationAlreadyInProgress, PkiRenewalFailed, PkiCouldNotReadCertError,\
    PkiAuthCheckFailed, PkiAuthCheckFailedRequest, PkiAuthCheckFailedInvalidChallenge,\
    CertRenewal, PkiSubManager
from .pki_manager_le import PkiLeManager

from .certificate_manager import CertificateManager
from .database_manager import DatabaseManager
from .dbutil import DbHostGroup, DbManagedSolution, DbManagedService, DbManagedHost, DbManagedTest, \
    DbManagedTestProfile, DbManagedCertIssue, DbManagedServiceToGroupAssoc, DbManagedSolutionToServiceAssoc, \
    DbKeychestAgent, DbManagedCertificate, Certificate, DbWatchTarget, DbDnsResolve, DbHandshakeScanJob, DbOwner,\
    DbManagedCertChain, DbManagedPrivate, DbHelper

from .server_management_utils import ManagementUtils
from .util_keychest import Encryptor
from .semaphore_manager import SemaphoreManager

import os
import time
import json
import math
import random
import logging
import threading
import collections
import base64
import datetime
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue

import sqlalchemy as salch
from events import Events
import requests
from requests.exceptions import RequestException


logger = logging.getLogger(__name__)


class ManagementModule(ServerModule):
    """
    Management monitor and processor
    Responsibilities:
      - Manage test records according to the database records
        - For each solution, service, service group and host create a new test record for certificate checking.
        - If host gets deleted / de-associated from the service, suspend testing on this host.

      - Watch test records, monitor certificates status
      - Issue new certificates, renew certificates (domain validation)
      - Deploy/sync new certs
    """

    def __init__(self, *args, **kwargs):
        super(ManagementModule, self).__init__(*args, **kwargs)
        self.redis_queue = None
        self.trace_logger = Tracelogger(logger)
        self.mod_agent = None

        self.local_data = threading.local()
        self.events = Events()

        self.job_queue = Queue(300)
        self.workers = []

        self.db_manager = None  # type: DatabaseManager
        self.cert_manager = None  # type: CertificateManager
        self.pki_manager = None  # type: PkiManager
        self.audit = AuditManager(disabled=True)
        self.syscfg = SysConfig(audit=self.audit)
        self.ansible = None  # type: AnsibleWrapper
        self.encryptor = None  # type: Encryptor
        self.semaphore_manager = SemaphoreManager()

    def init(self, server):
        """
        Initializes module with the server
        :param server:
        :return:
        """
        super(ManagementModule, self).init(server=server)
        self.mod_agent = server.mod_agent
        self.redis_queue = RedisQueue(redis_client=server.redis,
                                      default_queue='queues:management',
                                      event_queue='queues:management-evt')

        self.ansible = self.new_ansible_wrapper()
        self.local_data.ansible = None

        self.db_manager = server.db_manager
        self.cert_manager = server.cert_manager
        self.pki_manager = server.pki_manager
        self.encryptor = Encryptor(app_key=base64.b64decode(util.to_bytes(self.config.keychest_key)))

    def new_ansible_wrapper(self):
        """
        Constructs new Ansible wrapper
        :return:
        :rtype: AnsibleWrapper
        """
        return AnsibleWrapper(
            local_certbot_live=os.path.join(PkiLeManager.get_config_dir(self.config), 'live'),
            ansible_as_user='root',
            syscfg=self.syscfg
        )

    def get_thread_ansible_wrapper(self):
        """
        Thread local ansible wrapper
        :return:
        :rtype: AnsibleWrapper
        """
        if not hasattr(self.local_data, 'ansible') or self.local_data.ansible is None:
            self.local_data.ansible = self.new_ansible_wrapper()
        return self.local_data.ansible

    def shutdown(self):
        """
        Shutdown operation
        :return:
        """
        pass

    def run(self):
        """
        Kick off all running threads
        :return:
        """

        test_sync_thread = threading.Thread(target=self.main_test_sync, args=())
        test_sync_thread.setDaemon(True)
        test_sync_thread.start()

        mgmt_cert_sync_thread = threading.Thread(target=self.managed_certificate_sync, args=())
        mgmt_cert_sync_thread.setDaemon(True)
        mgmt_cert_sync_thread.start()

    #
    # Running
    #

    def main_test_sync(self):
        """
        Test target sync
        :return:
        """
        logger.info('Test target sync started')
        while self.is_running():
            self.server.interruptible_sleep(2)

            if self.config.management_disabled:
                continue

            try:
                s = self.db.get_session()
                q_sol = s.query(DbManagedSolution) \
                    .filter(DbManagedSolution.deleted_at is not None) \
                    .order_by(DbManagedSolution.id)

                # iterate over all solutions
                # iterate over all associated services
                # iterate over all associated host groups
                # iterate over all associated hosts
                # sync
                for sol in DbHelper.yield_limit(q_sol, DbManagedSolution.id):  # type: DbManagedSolution
                    if sol.deleted_at is not None:
                        continue

                    for svc in [x.service for x in sol.services]:  # type: DbManagedService
                        if svc.deleted_at is not None:
                            continue

                        mgmt_tests = s.query(DbManagedTest) \
                            .filter(DbManagedTest.solution == sol) \
                            .filter(DbManagedTest.service == svc) \
                            .all()  # type: list[DbManagedTest]

                        mgmt_hosts_tests = {x.host_id: x for x in mgmt_tests}  # type: dict[int, DbManagedTest]
                        mgmt_hosts_tests_enabled = {x: y for x, y in iteritems(mgmt_hosts_tests) if y.deleted_at is None}
                        all_hosts = {}  # type: dict[int, DbManagedHost]

                        for grp in [x.group for x in svc.groups]:  # type: DbHostGroup
                            if grp.deleted_at is not None:
                                continue

                            for host in [x.host for x in grp.hosts]:  # type: DbManagedHost
                                if host.deleted_at is not None:
                                    continue

                                all_hosts[host.id] = host

                        # Sync with host tests. For all new host add corresponding test record
                        # And for each test record in the DB
                        new_hosts_add = [x for x in all_hosts.values()
                                         if x.id not in mgmt_hosts_tests
                                         and x.id not in mgmt_hosts_tests_enabled]

                        tests_enable = [x for x in mgmt_hosts_tests.values()
                                        if x.deleted_at is not None
                                        and x.host_id is not None
                                        and x.host_id in all_hosts]

                        tests_disable = [x for x in mgmt_hosts_tests.values()
                                         if x.deleted_at is not None
                                         and x.host_id is not None
                                         and x.host_id not in all_hosts]

                        for new_tests in new_hosts_add:
                            ntest = DbManagedTest()
                            ntest.host_id = new_tests.id
                            ntest.solution_id = sol.id
                            ntest.service_id = svc.id
                            ntest.created_at = salch.func.now()
                            s.add(ntest)
                        s.commit()

                        stmt = salch.update(DbManagedTest) \
                            .where(DbManagedTest.id.in_([x.id for x in tests_enable])) \
                            .values(deleted_at=None, updated_at=salch.func.now())
                        s.execute(stmt)

                        stmt = salch.update(DbManagedTest) \
                            .where(DbManagedTest.id.in_([x.id for x in tests_disable])) \
                            .values(deleted_at=salch.func.now(), updated_at=salch.func.now())
                        s.execute(stmt)
                        s.commit()

            except Exception as e:
                logger.error('Exception in processing job %s' % e, exc_info=e)
                self.trace_logger.log(e)

            finally:
                util.silent_close(s)
                self.server.interruptible_sleep(10)

        logger.info('Test target sync terminated')

    def managed_certificate_sync(self):
        """
        Syncs managed certificates from the watch targets.
        Configuration task.
        :return:
        """
        logger.info('Managed cert sync started')
        while self.is_running():
            self.server.interruptible_sleep(2)

            if self.config.management_disabled:
                continue

            try:
                s = self.db.get_session()
                q_sol = s.query(DbManagedSolution) \
                    .filter(DbManagedSolution.deleted_at is not None) \
                    .order_by(DbManagedSolution.id)

                for sol in DbHelper.yield_limit(q_sol, DbManagedSolution.id):  # type: DbManagedSolution
                    if sol.deleted_at is not None:
                        continue

                    for svc in [x.service for x in sol.services]:  # type: DbManagedService
                        if svc.deleted_at is not None:
                            continue
                        if svc.svc_watch_id is None:
                            continue

                        # Fetch managed certificates. If present, continue to next record.
                        mgmt_certs = s.query(DbManagedCertificate)\
                            .filter(DbManagedCertificate.solution_id==sol.id)\
                            .filter(DbManagedCertificate.service_id==svc.id)\
                            .filter(DbManagedCertificate.record_deprecated_at==None)\
                            .all()
                        if len(mgmt_certs) > 0:
                            continue

                        # Load watch target, get the newest TLS scanned certificate.
                        wtarget = svc.watch_target  # type: DbWatchTarget
                        dns_scan = self.server.load_last_dns_scan_optim(s, wtarget.id)  # type: DbDnsResolve
                        if dns_scan is None:
                            continue

                        ips = [x[1] for x in dns_scan.dns_res]
                        prev_scans = self.server.load_last_tls_scan_last_dns(s, wtarget.id, ips)  # type: list[DbHandshakeScanJob]
                        if len(prev_scans) == 0:
                            continue

                        tls_scan = prev_scans[0]
                        mgmt_cert = DbManagedCertificate()
                        mgmt_cert.solution_id = sol.id
                        mgmt_cert.service_id = svc.id
                        mgmt_cert.certificate_id = tls_scan.cert_id_leaf
                        s.add(mgmt_cert)

                        # Load all alt names from the certificate if aux names are not filled in
                        if svc.svc_aux_names is None:
                            cert_db = s.query(Certificate)\
                                .filter(Certificate.id == tls_scan.cert_id_leaf)\
                                .first()  # type: Certificate

                            alt_names = cert_db.alt_names_arr if cert_db else []
                            svc.svc_aux_names = json.dumps(alt_names)

                        s.commit()

            except Exception as e:
                logger.error('Exception in processing job %s' % e, exc_info=e)
                self.trace_logger.log(e)

            finally:
                util.silent_close(s)
                self.server.interruptible_sleep(10)

        logger.info('Managed certs sync terminated')

    def load_active_tests(self, s, last_scan_margin=300, randomize=True):
        """
        Load test records to process

        :param s : SaQuery query
        :type s: SaQuery
        :param last_scan_margin: margin for filtering out records that were recently processed.
        :param randomize:
        :return:
        """
        q = s.query(DbManagedTest, DbManagedSolution, DbManagedService, DbManagedTestProfile,
                    DbManagedHost, DbKeychestAgent) \
            .join(DbManagedSolution, DbManagedSolution.id == DbManagedTest.solution_id) \
            .join(DbManagedService, DbManagedService.id == DbManagedTest.service_id) \
            .outerjoin(DbManagedHost, DbManagedHost.id == DbManagedTest.host_id) \
            .outerjoin(DbManagedTestProfile, DbManagedTestProfile.id == DbManagedService.test_profile_id) \
            .outerjoin(DbKeychestAgent, DbKeychestAgent.id == DbManagedService.agent_id) \
            .filter(DbManagedTest.deleted_at == None)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, float) else self.server.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1 * fact, fact))
            cur_margin = datetime.datetime.now() - datetime.timedelta(seconds=last_scan_margin)

            q = q.filter(
                salch.or_(
                    salch.and_(DbManagedTest.check_trigger == None,
                               salch.or_(
                                   DbManagedTest.last_scan_at < cur_margin,
                                   DbManagedTest.last_scan_at == None)
                               ),

                    salch.and_(DbManagedTest.check_trigger != None,
                               DbManagedTest.check_trigger < salch.func.now()),
                ))

        return q.group_by(DbManagedTest.id) \
            .order_by(DbManagedTest.last_scan_at)  # select the oldest scanned first

    def load_cert_checks(self, s, last_scan_margin=300, randomize=True):
        """
        Loads cert checks for renewal
        :param s:
        :param last_scan_margin:
        :param randomize:
        :return:
        """
        q = s.query(DbManagedCertificate, Certificate, DbManagedSolution, DbManagedService, DbManagedTestProfile,
                    DbKeychestAgent) \
            .join(DbManagedSolution, DbManagedSolution.id == DbManagedCertificate.solution_id) \
            .join(DbManagedService, DbManagedService.id == DbManagedCertificate.service_id) \
            .outerjoin(Certificate, Certificate.id == DbManagedCertificate.certificate_id) \
            .outerjoin(DbManagedTestProfile, DbManagedTestProfile.id == DbManagedService.test_profile_id) \
            .outerjoin(DbKeychestAgent, DbKeychestAgent.id == DbManagedService.agent_id) \
            .filter(DbManagedCertificate.record_deprecated_at == None)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, float) else self.server.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1 * fact, fact))
            cur_margin = datetime.datetime.now() - datetime.timedelta(seconds=last_scan_margin)

            q = q.filter(
                salch.or_(
                    salch.and_(DbManagedCertificate.check_trigger == None,
                               salch.or_(
                                   DbManagedCertificate.last_check_at < cur_margin,
                                   DbManagedCertificate.last_check_at == None)
                               ),

                    salch.and_(DbManagedCertificate.check_trigger != None,
                               DbManagedCertificate.check_trigger < salch.func.now()),
                ))

        return q.order_by(DbManagedCertificate.last_check_at)  # select the oldest scanned first

    def load_host_checks(self, s, last_scan_margin=60*60*12, randomize=True):
        """
        Loads host to check
        :param s:
        :param last_scan_margin:
        :param randomize:
        :return:
        """
        q = s.query(DbManagedHost, DbOwner) \
            .outerjoin(DbOwner, DbOwner.id == DbManagedHost.owner_id) \
            .filter(DbManagedHost.deleted_at == None)\
            .filter(DbManagedHost.has_ansible == 1)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, float) else self.server.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1 * fact, fact))
            cur_margin = datetime.datetime.now() - datetime.timedelta(seconds=last_scan_margin)

            q = q.filter(
                salch.or_(
                    salch.and_(DbManagedHost.ansible_check_trigger == None,
                               salch.or_(
                                   DbManagedHost.ansible_last_ping < cur_margin,
                                   DbManagedHost.ansible_last_ping == None)
                               ),

                    salch.and_(DbManagedHost.ansible_check_trigger != None,
                               DbManagedHost.ansible_check_trigger < salch.func.now()),
                ))

        return q.order_by(DbManagedHost.ansible_last_ping)  # select the oldest scanned first

    def load_service_checks(self, s, last_scan_margin=60*60*12, randomize=True):
        """
        Loads services to check
        :param s:
        :param last_scan_margin:
        :param randomize:
        :return:
        """
        q = s.query(DbManagedService, DbOwner, DbKeychestAgent) \
            .outerjoin(DbOwner, DbOwner.id == DbManagedService.owner_id) \
            .outerjoin(DbKeychestAgent, DbKeychestAgent.id == DbManagedService.agent_id) \
            .filter(DbManagedService.deleted_at == None)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, float) else self.server.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1 * fact, fact))
            cur_margin = datetime.datetime.now() - datetime.timedelta(seconds=last_scan_margin)

            q = q.filter(
                salch.or_(
                    salch.and_(DbManagedService.config_check_trigger == None,
                               salch.or_(
                                   DbManagedService.config_last_check < cur_margin,
                                   DbManagedService.config_last_check == None)
                               ),

                    salch.and_(DbManagedService.config_check_trigger != None,
                               DbManagedService.config_check_trigger < salch.func.now()),
                ))

        return q.order_by(DbManagedService.config_last_check)  # select the oldest scanned first

    def periodic_feeder(self, s):
        """
        Feed jobs for processing to the queue
        :param s:
        :return:
        """
        if self.config.management_disabled:
            return

        self.periodic_feeder_test(s)
        self.periodic_feeder_renew_check(s)
        self.periodic_feeder_service_check(s)
        self.periodic_feeder_host_check(s)

    def periodic_feeder_test(self, s):
        """
        Feed jobs - tester
        :param s:
        :return:
        """
        if self.server.periodic_queue_is_full():
            return

        cur_now = datetime.datetime.now()
        try:
            min_scan_margin = self.server.min_scan_margin()
            query = self.load_active_tests(s, last_scan_margin=min_scan_margin)

            for x in DbHelper.yield_limit(query, DbManagedTest.id, 100, primary_obj=lambda x: x[0]):
                if self.server.periodic_queue_is_full():
                    return
                if x[0].check_trigger is not None and x[0].check_trigger > cur_now:
                    continue

                job = PeriodicMgmtTestJob(target=x[0], periodicity=None,
                                          solution=x[1], service=x[2], test_profile=x[3], host=x[4], agent=x[5])
                self.server.periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            util.silent_rollback(s, False)
            logger.error('Exception loading watch jobs %s' % e, exc_info=e)
            self.trace_logger.log(e)
            raise

    def periodic_feeder_renew_check(self, s):
        """
        Feed jobs - renew checking
        Based on existing certificate record.
        :param s:
        :return:
        """
        if self.server.periodic_queue_is_full():
            return

        cur_now = datetime.datetime.now()
        try:
            min_scan_margin = self.server.min_scan_margin()
            query = self.load_cert_checks(s, last_scan_margin=min_scan_margin)

            for x in DbHelper.yield_limit(query, DbManagedCertificate.id, 100, primary_obj=lambda x: x[0]):
                if self.server.periodic_queue_is_full():
                    return
                if x[0].check_trigger is not None and x[0].check_trigger > cur_now:
                    continue

                job = PeriodicMgmtRenewalJob(managed_certificate=x[0], certificate=x[1],
                                             solution=x[2], target=x[3], test_profile=x[4], agent=x[5])
                self.server.periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            util.silent_rollback(s, False)
            logger.error('Exception loading watch jobs %s' % e, exc_info=e)
            self.trace_logger.log(e)
            raise

    def periodic_feeder_host_check(self, s):
        """
        Feed jobs - host checking

        :param s:
        :return:
        """
        if self.server.periodic_queue_is_full():
            return

        cur_now = datetime.datetime.now()
        try:
            min_scan_margin = self.server.min_scan_margin()
            query = self.load_host_checks(s, last_scan_margin=min_scan_margin)

            for x in DbHelper.yield_limit(query, DbManagedHost.id, 100, primary_obj=lambda x: x[0]):
                if self.server.periodic_queue_is_full():
                    return
                if x[0].ansible_check_trigger is not None and x[0].ansible_check_trigger > cur_now:
                    continue

                job = PeriodicMgmtHostCheckJob(target=x[0], agent=x[1])
                self.server.periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            util.silent_rollback(s, False)
            logger.error('Exception loading host check jobs %s' % e, exc_info=e)
            self.trace_logger.log(e)
            raise

    def periodic_feeder_service_check(self, s):
        """
        Feed jobs - service checking

        :param s:
        :return:
        """
        if self.server.periodic_queue_is_full():
            return

        cur_now = datetime.datetime.now()
        try:
            min_scan_margin = self.server.min_scan_margin()
            query = self.load_service_checks(s, last_scan_margin=min_scan_margin)

            for x in DbHelper.yield_limit(query, DbManagedService.id, 100, primary_obj=lambda x: x[0]):
                if self.server.periodic_queue_is_full():
                    return
                if x[0].config_check_trigger is not None and x[0].config_check_trigger > cur_now:
                    continue

                job = PeriodicMgmtServiceCheckJob(service=x[0], owner=x[1], agent=x[2])
                self.server.periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            util.silent_rollback(s, False)
            logger.error('Exception loading host check jobs %s' % e, exc_info=e)
            self.trace_logger.log(e)
            raise

    def periodic_job_update_last_scan(self, job):
        """
        Update last scan of the job
        :param job:
        :return: True if job was consumed
        """
        if not isinstance(job, (PeriodicMgmtRenewalJob, PeriodicMgmtTestJob, PeriodicMgmtHostCheckJob,
                                PeriodicMgmtServiceCheckJob)):
            return False

        s = self.db.get_session()
        try:
            if isinstance(job, PeriodicMgmtTestJob):
                job.target = s.merge(job.target)
                stmt = DbManagedTest.__table__.update() \
                    .where(DbManagedTest.id == job.target.id) \
                    .values(last_scan_at=salch.func.now())

            elif isinstance(job, PeriodicMgmtRenewalJob):
                job.managed_certificate = s.merge(job.managed_certificate)
                stmt = DbManagedCertificate.__table__.update() \
                    .where(DbManagedCertificate.id == job.managed_certificate.id) \
                    .values(last_check_at=salch.func.now())

            elif isinstance(job, PeriodicMgmtHostCheckJob):
                return True

            elif isinstance(job, PeriodicMgmtServiceCheckJob):
                return True

            else:
                return False

            s.execute(stmt)
            s.commit()

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

        return True

    def trigger_test_managed_tests(self, s, solution_id, service_id):
        """
        Triggers testing for managed tests by setting last scan at to null
        :param s:
        :param solution_id:
        :param service_id:
        :return:
        """
        try:
            stmt = DbManagedTest.__table__.update() \
                .where(DbManagedTest.solution_id == solution_id) \
                .where(DbManagedTest.service_id == service_id) \
                .values(last_scan_at=None)
            s.execute(stmt)
            s.commit()

        finally:
            util.silent_rollback(s, False)

        return True

    def create_renew_record(self, job, req_data=None, new_cert=None, status=None):
        """
        Stores renewal record
        :param job:
        :type job: PeriodicMgmtRenewalJob
        :param req_data:
        :param new_cert:
        :type new_cert: Certificate
        :return:
        :rtype: DbManagedCertIssue
        """
        issue = DbManagedCertIssue()
        issue.solution_id = job.solution.id
        issue.service_id = job.target.id
        issue.certificate_id = job.certificate.id if job.certificate else None
        if new_cert:
            issue.new_certificate_id = new_cert.id
        issue.request_data = json.dumps(req_data)
        issue.created_at = salch.func.now()
        issue.last_issue_at = salch.func.now()
        issue.last_issue_status = status
        return issue

    def update_object(self, s, target, **kwargs):
        """
        General object update method
        :param s:
        :param target:
        :param kwargs:
        :return:
        """
        for key, value in iteritems(kwargs):
            setattr(target, key, value)

        return s.merge(target)

    def finish_test_object(self, s, target, last_scan=True, **kwargs):
        """
        Updates test job
        :param target:
        :type target: Union[DbManagedTest, DbManagedCertificate, DbManagedService]
        :param last_scan:
        :param kwargs:
        :return:
        """
        if last_scan:
            target.last_scan_at = salch.func.now()
        for key, value in iteritems(kwargs):
            setattr(target, key, value)

        return s.merge(target)

    def process_periodic_job(self, job):
        """
        Process my jobs in the worker thread.
        :param job:
        :type job: PeriodicMgmtTestJob|PeriodicMgmtRenewalJob
        :return:
        """

        if isinstance(job, PeriodicMgmtTestJob):
            return self.process_periodic_job_test(job)

        if isinstance(job, PeriodicMgmtRenewalJob):
            return self.process_periodic_job_renew(job)

        if isinstance(job, PeriodicMgmtHostCheckJob):
            return self.process_periodic_job_host_check(job)

        if isinstance(job, PeriodicMgmtServiceCheckJob):
            return self.process_periodic_job_service_check(job)

        return False

    def process_periodic_job_renew(self, job):
        """
        Check if the renewal is needed
        :param job:
        :type job: PeriodicMgmtRenewalJob
        :return:
        """
        if not isinstance(job, PeriodicMgmtRenewalJob):
            logger.error('Invalid job passed (renew): %s' % job)
            return False

        logger.debug('Processing Mgmt renew job: %s, qsize: %s, sems: %s'
                     % (job, self.server.watcher_job_queue.qsize(), self.server.periodic_semaphores()))

        s = None
        try:
            s = self.db.get_session()

            self.process_renew_job_body(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.results.is_failed():
                logger.info('Renew scan job failed: %s' % (job.results.is_failed()))
                job.attempts += 1
                job.success_scan = False

            else:
                job.success_scan = True

        except InvalidInputData as id:
            logger.debug('Invalid test input')
            job.success_scan = True  # job is deemed processed
            # self.finish_test_object(s, job.target, last_scan_status=-1)

        except Exception as e:
            logger.debug('Exception when processing the mgmt renew process job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

        return True

    def process_periodic_job_test(self, job):
        """
        Process my jobs in the worker thread.
        :param job:
        :type job: PeriodicMgmtTestJob
        :return:
        """
        if not isinstance(job, PeriodicMgmtTestJob):
            return False

        logger.debug('Processing Mgmt job: %s, qsize: %s, sems: %s'
                     % (job, self.server.watcher_job_queue.qsize(), self.server.periodic_semaphores()))

        s = None
        try:
            s = self.db.get_session()

            self.process_test_job_body(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.results.is_failed():
                logger.info('Test scan job failed: %s' % (job.results.is_failed()))
                job.attempts += 1
                job.success_scan = False

            else:
                job.success_scan = True

        except InvalidInputData as id:
            logger.debug('Invalid test input')
            job.success_scan = True  # job is deemed processed
            self.finish_test_object(s, job.target, last_scan_status=-1)

        except InvalidHostname as ih:
            logger.debug('Invalid host')
            job.success_scan = True  # TODO: back-off / disable, fatal error
            self.finish_test_object(s, job.target, last_scan_status=-2)

        except Exception as e:
            logger.debug('Exception when processing the mgmt process job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

        return True

    def process_periodic_job_host_check(self, job):
        """
        Process my jobs in the worker thread.
        :param job:
        :type job: PeriodicMgmtHostCheckJob
        :return:
        """
        if not isinstance(job, PeriodicMgmtHostCheckJob):
            return False

        logger.debug('Processing Mgmt host check job: %s, qsize: %s, sems: %s'
                     % (job, self.server.watcher_job_queue.qsize(), self.server.periodic_semaphores()))

        s = None
        try:
            s = self.db.get_session()

            self.process_host_check_job_body(s, job)
            self.process_host_config_check_job_body(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.results.is_failed():
                logger.info('Test scan job failed: %s' % (job.results.is_failed()))
                job.attempts += 1
                job.success_scan = False

            else:
                job.success_scan = True

        except InvalidInputData as id:
            logger.debug('Invalid test input')
            job.success_scan = True  # job is deemed processed
            self.finish_test_object(s, job.target, last_scan=False,
                                    ansible_last_ping=salch.func.now(), ansible_last_status=-1)

        except Exception as e:
            logger.debug('Exception when processing the mgmt process job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

        return True

    def process_periodic_job_service_check(self, job):
        """
        Process my jobs in the worker thread.
        :param job:
        :type job: PeriodicMgmtServiceCheckJob
        :return:
        """
        if not isinstance(job, PeriodicMgmtServiceCheckJob):
            return False

        logger.debug('Processing Mgmt service check job: %s, qsize: %s, sems: %s'
                     % (job, self.server.watcher_job_queue.qsize(), self.server.periodic_semaphores()))

        s = None
        try:
            s = self.db.get_session()

            self.process_service_check_job_body(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.results.is_failed():
                logger.info('Test scan job failed: %s' % (job.results.is_failed()))
                job.attempts += 1
                job.success_scan = False

            else:
                job.success_scan = True

        except InvalidInputData as id:
            logger.debug('Invalid test input')
            job.success_scan = True  # job is deemed processed
            self.finish_test_object(s, job.service, last_scan=False,
                                    config_last_check=salch.func.now(), config_last_status=-1)

        except Exception as e:
            logger.debug('Exception when processing the mgmt process job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

        return True

    def process_renew_job_body(self, s, job):
        """
        Renew job processing
        - Check if the renewal is needed for the certificate.
        - If renewal is needed do the renewal process now.

        :param s:
        :param job:
        :type job: PeriodicMgmtRenewalJob
        :return:
        """

        def finish_task(**kwargs):
            """Simple finish callback"""
            job.results.ok()
            kwargs.setdefault('check_trigger', None)
            kwargs.setdefault('last_check_at', salch.func.now())
            self.finish_test_object(s, job.managed_certificate, last_scan=False, **kwargs)
            s.commit()

        # Is the certificate eligible for renewal?
        # if LE then 1 month before expiration. CA: job.target.svc_ca
        # For now all CAs will have 28 days before expiration renewal period.
        renewal_period = datetime.timedelta(days=28)

        if not job.managed_certificate:
            # Certificate not yet linked
            logger.debug('Not renewing certificate - not linked %s' % job.target.id)
            finish_task()
            return

        if job.certificate and datetime.datetime.now() + renewal_period <= job.certificate.valid_to:
            # No renewal needed here
            logger.debug('Not renewing - cert valid: %s' % job.target.id)
            finish_task()
            return

        # Attempt renewal now.
        # For now support only simple use cases. E.g., LetsEncrypt renewal.
        # LE Renewal: call Certbot, fetch new certificate from the cert store, deploy later.
        # LE certbot should run on the agent. For now on the master directly.
        job.target = s.merge(job.target)
        pki_type = job.target.svc_ca.pki_type if job.target.svc_ca is not None else None

        pki_mgr = self.pki_manager.resolve_manager(pki_type)
        if not pki_mgr:
            logger.info('CA not supported for renewal: %s' % pki_type)
            finish_task()
            return

        ren = pki_mgr.renew_cert(s=s, job=job)
        self.renew_cert(s, job, pki_mgr, ren, finish_task)

    def renew_cert(self, s, job, pki_mgr, ren, finish_task):
        """
        Cert renew logic

        :param s:
        :param job:
        :param pki_mgr:
        :type pki_mgr: PkiSubManager
        :param ren:
        :type ren: CertRenewal
        :param finish_task:
        :return:
        """
        domains = ren.domains

        req_data = collections.OrderedDict()
        req_data['CA'] = job.target.svc_ca.id
        req_data['CA_type'] = pki_mgr.ca_type()
        req_data['domains'] = ren.domains
        renew_record = self.create_renew_record(job, req_data=req_data)

        try:
            ren.renew()

        except PkiOperationAlreadyInProgress as e:
            logger.debug('Certbot lock not acquired for %s, back-off' % ren.domains[0])
            finish_task(last_check_status=-15,
                        check_trigger=datetime.datetime.now() + datetime.timedelta(seconds=30))
            return

        except PkiRenewalFailed as e:
            logger.warning('Renewal failed: %s' % e)

            renew_record.last_issue_status = -2
            renew_record.last_issue_data = json.dumps(e.fail_data)
            s.add(renew_record)
            finish_task(last_check_status=-2)
            self.events.on_renew_fail(job, e)
            return

        except PkiCouldNotReadCertError as e:
            logger.warning('Could not read certificates')

        # if certificate has changed, load certificate file to the database, update, signalize,...
        if not ren.cert_changed:
            logger.debug('Certificate did not change for mgmt cert: %s, domain: %s' % (job.target.id, domains[0]))
            renew_record.last_issue_status = 2
            s.add(renew_record)
            finish_task(last_check_status=2)
            return

        # Load the full cert chain, with the newest issued cert in the first entry
        chain_arr = CertificateManager.pem_chain_to_array(ren.chain_data)
        res = self.cert_manager.process_full_chain(s, cert_chain=chain_arr, is_der=False)

        all_certs = res[0]
        if len(all_certs) == 0:
            logger.warning('LE Chain is empty')
            return

        leaf_cert = all_certs[0]
        chain_certs = all_certs[1:]

        # All base model certificates are in the DB now
        # Check existence of the chaining records and private key records.
        privkey_hash = CertificateManager.get_privkey_hash(pem=ren.priv_data)
        priv_db = s.query(DbManagedPrivate)\
            .filter(DbManagedPrivate.private_hash == privkey_hash)\
            .first()

        if priv_db is None:
            priv_db = DbManagedPrivate()
            priv_db.private_hash = privkey_hash
            priv_db.certificate_id = leaf_cert.id
            priv_db.private_data = self.encryptor.encrypt(util.to_string(ren.priv_data))
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

    def process_test_job_body(self, s, job):
        """
        Process test job

        Test certificate status / freshness on the given host. May be:
          - classic watch_target TLS test, locked on particular IP address
          - physical file test
          - API call certificate test

        When the certificate for the service is marked for renewal, start renewal and deployment process

        :param s:
        :param job:
        :type job: PeriodicMgmtTestJob
        :return:
        """

        def finish_task(test=None, **kwargs):
            """Simple finish callback"""
            job.results.ok()
            kwargs.setdefault('check_trigger', None)
            kwargs.setdefault('last_scan_at', salch.func.now())
            self.finish_test_object(s, test if test else job.target, **kwargs)
            s.commit()

        if job.host is None:
            logger.info('Unsupported check without host ID')
            finish_task()
            return

        # Refresh in job session
        job.target = s.merge(job.target)
        job.service = s.merge(job.service)
        job.host = s.merge(job.host)

        # Get all managed certificates associated to the service
        mgmt_certs = list(s.query(DbManagedCertificate) \
                          .filter(DbManagedCertificate.solution_id == job.solution.id) \
                          .filter(DbManagedCertificate.service_id == job.service.id) \
                          .filter(DbManagedCertificate.record_deprecated_at == None) \
                          .filter(DbManagedCertificate.certificate_id is not None) \
                          .all())  # type: list[DbManagedCertificate]

        if len(mgmt_certs) == 0:
            logger.debug('Nothing to sync for svc %d' % job.service.id)
            finish_task(last_scan_status=-1)
            return

        max_cert_id = max([x.certificate_id for x in mgmt_certs])
        if job.target.max_certificate_id_deployed >= max_cert_id:
            logger.debug('All certs up to date on host %s' % job.host.id)
            finish_task(last_scan_status=-2)
            return

        # Currently only one certificate per service is supported.
        # Later we will need to locate the certificate somehow for the sync.
        try:
            ansible = self.get_thread_ansible_wrapper()
            ret = ansible.deploy_certs(host=job.host, service=job.service, primary_domain=job.service.svc_name)
            ret_code = ret[0]
            test = job.target

            out = ret[1]
            out_json = json.dumps(out)

            new_max_deployed_id = max_cert_id if ret_code == 0 else test.max_certificate_id_deployed
            job.target = self.update_object(s, test,
                                            last_scan_status=ret[0],
                                            last_scan_data=out_json,
                                            max_certificate_id_deployed=new_max_deployed_id)

            finish_task(test=job.target, last_scan_status=ret_code)

            self.events.on_cert_deploy_finished(ret[0] == 0, job, ret)

        except Exception as e:
            util.silent_rollback(s)
            logger.warning('Exception in cert sync %s for test %s' % (e, job.target.id), exc_info=e)
            finish_task(last_scan_status=-10, last_scan_data='%s' % e)
            return

    def process_host_check_job_body(self, s, job):
        """
        Check host with Ansible, gets facts

        :param s:
        :param job:
        :type job: PeriodicMgmtHostCheckJob
        :return:
        """
        def finish_task(host=None, **kwargs):
            """Simple finish callback"""
            job.results.ok()
            kwargs.setdefault('ansible_check_trigger', None)
            kwargs.setdefault('ansible_last_ping', salch.func.now())
            self.finish_test_object(s, host if host else job.target, last_scan=False, **kwargs)
            s.commit()

        if not job.target.has_ansible:
            logger.warning('Host check of non-Ansible host %s' % job.target.id)
            finish_task(ansible_last_status=-1)
            return

        ansible = self.get_thread_ansible_wrapper()
        try:
            ret = ansible.get_facts(job.target.host_addr)
            host = job.target
            out = ret[1]
            out_task = ansible.get_ansible_tasks_by_host(out)
            if not util.is_empty(out_task):
                out_task = out_task[out_task.keys()[0]]

            facts_json = json.dumps(out_task)
            host = self.update_object(s, host, ansible_last_status=ret[0], host_ansible_facts=facts_json)

            finish_task(host=host)
            logger.info('Ansible check finished: %s for host %s, len(fact): %s' % (ret[0], host.id, len(facts_json)))

            self.events.on_host_check_finished(ret[0] == 0, job, ret)

        except Exception as e:
            util.silent_rollback(s)
            logger.error('Exception on Ansible check %s' % e, exc_info=e)
            finish_task(ansible_last_status=-1)

    def process_host_config_check_job_body(self, s, job):
        """
        Host configuration check w.r.t. service (e.g., .well-known forwarding test)
        TODO: check (host, svc) pairs. Host can have multiple services, such tests should be independent.

        :param s:
        :param job:
        :type job: PeriodicMgmtHostCheckJob
        :return:
        """
        return False

    def process_service_check_job_body(self, s, job):
        """
        Check service configuration correctness - typically correctness of the
        .well-known redirect. Depending on the associated PKI type.

        :param s:
        :param job:
        :type job: PeriodicMgmtServiceCheckJob
        :return:
        """
        def finish_task(service=None, **kwargs):
            """Simple finish callback"""
            job.results.ok()
            kwargs.setdefault('config_check_trigger', None)
            kwargs.setdefault('config_last_check', salch.func.now())
            self.finish_test_object(s, service if service else job.service, last_scan=False, **kwargs)
            s.commit()

        job.service = s.merge(job.service)
        pki_type = job.service.svc_ca.pki_type if job.service.svc_ca is not None else None

        pki_mgr = self.pki_manager.resolve_manager(pki_type)
        if not pki_mgr:
            logger.debug('Svc with PKI %s check not implemented' % pki_type)
            finish_task()
            return

        attempts = 3
        timeout = 10
        domains = ManagementUtils.get_service_domains(job.service)
        check_result = collections.OrderedDict()
        check_fails = 0

        # Checking each domain redirect.
        for domain in domains:
            try:
                res = pki_mgr.test_renew_config(domain, job=job, attempts=attempts, timeout=timeout)
                check_result[domain] = {'status': '0', 'res': res}

            except PkiAuthCheckFailedRequest as re:
                check_fails += 1
                check_result[domain] = {'status': '-2', 'errno': re.cause.errno, 'e': str(re)}
                logger.error('RequestException on Svc check %s, domain: %s' % (re, domain), exc_info=re)

            except PkiAuthCheckFailedInvalidChallenge as e:
                check_fails += 1
                check_result[domain] = {'status': '-3', 'e': str(e)}
                logger.error('Invalid challenge on Svc check %s, domain: %s' % (e, domain), exc_info=e)

            except PkiAuthCheckFailed as e:
                check_fails += 1
                check_result[domain] = {'status': '-1', 'e': str(e)}
                logger.error('Exception on Svc check %s, domain: %s' % (e, domain), exc_info=e)

        # Save check status
        final_status = 0 if check_fails == 0 else 1
        check_data = json.dumps(check_result)
        logger.info('Service check finished, fails: %s for service %s' % (check_fails, job.service.id))

        finish_task(service=job.service,
                    config_last_status=final_status,
                    config_last_data=check_data)

        self.events.on_service_check_finished(final_status == 0, job, check_data)

    @staticmethod
    def get_service_domains(svc):
        """
        Returns list of domains for the service
        :param svc:
        :type svc: DbManagedService
        :return:
        """
        domains = [svc.svc_name]
        if svc.svc_aux_names:
            domains += json.loads(svc.svc_aux_names)
        return domains

