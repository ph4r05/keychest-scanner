#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key management scanning, renewal
"""

from past.builtins import basestring    # pip install future
from past.builtins import cmp
from future.utils import iteritems

import util
from config import Config
from redis_queue import RedisQueue
import redis_helper as rh
from trace_logger import Tracelogger
from errors import Error, InvalidHostname, ServerShuttingDown, InvalidInputData
from server_jobs import JobTypes, BaseJob, PeriodicJob, PeriodicApiProcessJob, PeriodicMgmtTestJob, ScanResults
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, DbLastScanCacheType, IpType
from server_module import ServerModule
from server_data import EmailArtifact, EmailArtifactTypes
from dbutil import DbKeycheckerStats, DbHostGroup, DbManagedSolution, DbManagedService, DbManagedHost, DbManagedTest, \
    DbManagedTestProfile, DbManagedCertIssue, DbManagedServiceToGroupAssoc, DbManagedSolutionToServiceAssoc, \
    DbKeychestAgent, DbHelper

import time
import json
import math
import random
import logging
import threading
import collections
import base64
import imaplib
import email
import email.message as emsg
from datetime import datetime, timedelta
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue

import sqlalchemy as salch


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
        self.job_queue = Queue(300)
        self.workers = []

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

        # email_thread = threading.Thread(target=self.main_scan_emails, args=())
        # email_thread.setDaemon(True)
        # email_thread.start()

        # Worker start
        for worker_idx in range(0, self.config.workers_roca):
            t = threading.Thread(target=self.worker_main, args=(worker_idx,))
            t.setDaemon(True)
            t.start()

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
                logger.error('Exception in processing job %s' % (e,))
                self.trace_logger.log(e)

            finally:
                util.silent_close(s)
                self.server.interruptible_sleep(10)

        logger.info('Test target sync terminated')

    def worker_main(self, idx):
        """
        Worker main entry method - worker thread executes this.
        Processes job_queue jobs, redis enqueued / email queue.

        :param idx:
        :return:
        """
        self.local_data.idx = idx
        logger.info('Worker %02d started' % idx)

        while self.is_running():
            job = None
            try:
                job = self.job_queue.get(True, timeout=1.0)
            except QEmpty:
                time.sleep(0.1)
                continue

            try:
                # Process job in try-catch so it does not break worker
                logger.info('[%02d] Processing job' % (idx,))
                jtype, jobj = job
                # if jtype == 'redis':
                #     self.process_redis_job(jobj)
                # elif jtype == 'email':
                #     self.process_email_job(jobj)
                # else:
                #     pass

            except Exception as e:
                logger.error('Exception in processing job %s: %s' % (e, job))
                self.trace_logger.log(e)

            finally:
                self.job_queue.task_done()
        logger.info('Worker %02d terminated' % idx)

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

            q = q.filter(salch.or_(
                DbManagedTest.last_scan_at < cur_margin,
                DbManagedTest.last_scan_at == None
            ))

        return q.group_by(DbManagedTest.id) \
            .order_by(DbManagedTest.last_scan_at)  # select the oldest scanned first

    def periodic_feeder(self, s):
        """
        Feed jobs for processing to the queue
        :param s:
        :return:
        """
        self.periodic_feeder_test(s)

    def periodic_feeder_test(self, s):
        """
        Feed jobs - tester
        :param s:
        :return:
        """
        if self.server.periodic_queue_is_full():
            return

        try:
            min_scan_margin = self.server.min_scan_margin()
            query = self.load_active_tests(s, last_scan_margin=min_scan_margin)

            for x in DbHelper.yield_limit(query, DbManagedTest.id, 100):
                if self.server.periodic_queue_is_full():
                    return

                job = PeriodicMgmtTestJob(target=x[0], periodicity=None,
                                          solution=x[1], service=x[2], test_profile=x[3], host=x[4], agent=x[5])
                self.server.periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            s.rollback()
            logger.error('Exception loading watch jobs %s' % e)
            self.trace_logger.log(e)
            raise

    def periodic_job_update_last_scan(self, job):
        """
        Update last scan of the job
        :param job:
        :return: True if job was consumed
        """
        if not isinstance(job, PeriodicMgmtTestJob):
            return False

        s = self.db.get_session()
        try:
            stmt = DbManagedTest.__table__.update() \
                .where(DbManagedTest.id == job.target.id) \
                .values(last_scan_at=salch.func.now())
            s.execute(stmt)
            s.commit()

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

        return True

    def finish_test_object(self, s, target, **kwargs):
        """
        Updates test job
        :param target:
        :type target: DbManagedTest
        :param kwargs:
        :return:
        """
        target.last_scan_at = salch.func.now()
        for key, value in iteritems(kwargs):
            setattr(target, key, value)

        return s.merge(target)

    def process_periodic_job(self, job):
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

            self.process_job_body(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.scan_test_results.is_failed():
                logger.info('Test scan job failed: %s' % (job.scan_test_results.is_failed()))
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

    def process_job_body(self, s, job):
        """
        Process test job
        :param s:
        :param job:
        :type job: PeriodicMgmtTestJob
        :return:
        """
        pass

