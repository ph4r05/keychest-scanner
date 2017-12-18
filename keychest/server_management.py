#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key management scanning, renewal
"""

from past.builtins import basestring    # pip install future
from past.builtins import cmp

import util
from config import Config
from redis_queue import RedisQueue
import redis_helper as rh
from trace_logger import Tracelogger
from errors import Error, InvalidHostname, ServerShuttingDown
from server_jobs import JobTypes, BaseJob, PeriodicJob, PeriodicReconJob, PeriodicIpScanJob, ScanResults
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, DbLastScanCacheType, IpType
from server_module import ServerModule
from server_data import EmailArtifact, EmailArtifactTypes
from dbutil import DbKeycheckerStats
import keys_tools
from roca import detect

import os
import time
import json
import logging
import threading
import collections
import base64
import imaplib
import email
import email.message as emsg
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue


from M2Crypto import SMIME, X509, BIO

logger = logging.getLogger(__name__)


class ManagementModule(ServerModule):
    """
    Management monitor and processor
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

        # scan_thread = threading.Thread(target=self.scan_redis_jobs, args=())
        # scan_thread.setDaemon(True)
        # scan_thread.start()
        #
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

