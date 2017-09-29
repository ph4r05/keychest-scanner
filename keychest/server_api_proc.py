#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API processor module.

Processes API requests to insert / add the object.
e.g. request of the user to add a certificate to the monitoring send by public API on KC.

"""

from past.builtins import cmp

import util
from config import Config
from redis_queue import RedisQueue
import redis_helper as rh
from trace_logger import Tracelogger
from errors import Error, InvalidHostname, ServerShuttingDown
from server_jobs import JobTypes, BaseJob, PeriodicJob, PeriodicReconJob, PeriodicIpScanJob, ScanResults
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, CrtshInputType, DbLastScanCacheType, IpType
from server_module import ServerModule

import time
import json
import logging
import threading
import collections
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue


logger = logging.getLogger(__name__)


class ServerApiProc(ServerModule):
    """
    Server API processor
    """

    def __init__(self, *args, **kwargs):
        super(ServerApiProc, self).__init__(*args, **kwargs)

        self.redis_queue = None
        self.trace_logger = Tracelogger(logger)

        self.local_data = threading.local()
        self.job_queue = Queue(300)
        self.workers = []

    def init(self, server):
        """
        Initializes module with the server
        :param server:
        :return:
        """
        super(ServerApiProc, self).init(server=server)
        self.redis_queue = RedisQueue(redis_client=server.redis,
                                      default_queue='queues:tester',
                                      event_queue='queues:tester-evt')

    def run(self):
        """
        Kick off all running threads
        :return:
        """
        super(ServerApiProc, self).run()

    #
    # Interface - Redis interactive jobs
    #

    def process_redis_job(self, job):
        """
        Main redis job processor
        Handles job logic as implemented in Laravel.
        e.g., removes jobs from delay/reserved queues when finished.
        :param job:
        :return:
        """
        try:
            # Process job in try-catch so it does not break worker
            logger.info('New job: %s' % json.dumps(job.decoded, indent=4))
            rh.mark_failed_if_exceeds(job)

            # Here we will fire off the job and let it process. We will catch any exceptions so
            # they can be reported to the developers logs, etc. Once the job is finished the
            # proper events will be fired to let any listeners know this job has finished.
            self.on_redis_job(job)

            # Once done, delete job from the queue
            if not job.is_deleted_or_released():
                job.delete()

        except Exception as e:
            logger.error('Exception in processing job %s' % (e,))
            self.trace_logger.log(e)

            rh.mark_failed_exceeds_attempts(job, 5, e)
            if not job.is_deleted_or_released() and not job.failed:
                job.release()

    def on_redis_job(self, job):
        """
        Main redis job router. Determines which command should be executed.
        :param job:
        :return:
        """
        payload = job.decoded
        if payload is None or 'data' not in payload:
            logger.warning('Invalid job detected: %s' % json.dumps(payload))
            job.delete()
            return

        data = payload['data']
        cmd = data['commandName']
        if cmd == 'App\\Jobs\\TesterJob':
            self.on_redis_test_job(job)
        else:
            logger.warning('Unknown job: %s' % cmd)
            job.delete()
            return

    def augment_redis_scan_job(self, job=None, data=None):
        """
        Augments job with retry counts, timeouts and so on.
        :param RedisJob job:
        :param data:
        :return:
        """
        if job is not None:
            data = job.decoded['data']['json']

        scan_type = None
        if 'scan_type' in data:
            scan_type = data['scan_type']

        sys_params = collections.OrderedDict()
        sys_params['retry'] = 1
        sys_params['timeout'] = 4
        sys_params['mode'] = JobType.UI

        if scan_type == 'planner':
            sys_params['retry'] = 2
            sys_params['timeout'] = 15  # tls & connect scan
            sys_params['mode'] = JobType.BACKGROUND

        data['sysparams'] = sys_params
        return data

    def load_redis_job(self):
        """
        Loads redis job from the queue. Blocking behavior for optimized performance
        :return:
        """
        job = self.redis_queue.pop(blocking=True, timeout=1)
        if job is None:
            raise QEmpty()

        return job

    def scan_redis_jobs(self):
        """
        Blocking method scanning redis jobs.
        Should be run in dedicated thread or in the main thread as it blocks the execution.
        :return:
        """
        cur_size = self.redis_queue.size()
        logger.info('Redis total queue size: %s' % cur_size)

        while self.is_running():
            job = None
            try:
                job = self.load_redis_job()

            except QEmpty:
                time.sleep(0.01)
                continue

            try:
                self.job_queue.put(('redis', job))

            except Exception as e:
                logger.error('Exception in processing job %s' % (e,))
                self.trace_logger.log(e)

            finally:
                pass
        logger.info('Queue scanner terminated')

    #
    # Email scanning
    #

    def process_email_job(self, job):
        """
        Processes email job by the worker
        :param job:
        :return:
        """
        # TODO: analyze email contents
        # TODO: fingerprint SMIME / PGP
        # TODO: send email with the results
        # TODO: move email to the DONE folder

    def main_scan_emails(self):
        """
        Main thread for scanning email inbox for jobs.
        On job is processed, move email to PROGRESS folder.
        If job is in the progress folder for too long, expire it.
        :return:
        """
        while self.is_running():
            job = None
            try:
                # TODO: load new emails, create job from it
                pass

            except QEmpty:
                time.sleep(0.01)
                continue

            try:
                self.job_queue.put(('email', job))

            except Exception as e:
                logger.error('Exception in processing job %s' % (e,))
                self.trace_logger.log(e)

            finally:
                pass
        logger.info('Email scanner terminated')

    #
    # Running
    #

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
                logger.info('[%02d] Processing job' % (idx, ))
                jtype, jobj = job
                if jtype == 'redis':
                    self.process_redis_job(jobj)
                elif jtype == 'email':
                    self.process_email_job(jobj)
                else:
                    pass

            except Exception as e:
                logger.error('Exception in processing job %s: %s' % (e, job))
                self.trace_logger.log(e)

            finally:
                self.job_queue.task_done()
        logger.info('Worker %02d terminated' % idx)

    def on_redis_test_job(self, job):
        """
        Redis job for key test - run in the worker
        :param job:
        :return:
        """
        self.augment_redis_scan_job(job)

        # TODO: extract info to test
        job_data = job.decoded['data']['json']
        assoc_id = job_data['id']

        s = None
        try:
            # TODO: do the test
            # TODO: pass the result of the test in the event
            pass
            # s = self.db.get_session()
            #
            # assoc = s.query(DbSubdomainWatchAssoc).filter(DbSubdomainWatchAssoc.id == assoc_id).first()
            # if assoc is None:
            #     return

            # self.auto_fill_assoc(s, assoc)
            # s.commit()

        except Exception as e:
            logger.warning('Tester job exception: %s' % e)
            self.trace_logger.log(e)

        finally:
            util.silent_close(s)

