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
from server_jobs import JobTypes, BaseJob, PeriodicJob, ScanResults, PeriodicApiProcessJob
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, CrtshInputType, DbLastScanCacheType, IpType
from server_module import ServerModule
from dbutil import DbApiWaitingObjects, DbApiKey

import time
import json
import math
import random
import datetime
import types
import logging
import threading
import collections
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue


import sqlalchemy as salch
from sqlalchemy.orm.query import Query as SaQuery
from sqlalchemy import case, literal_column
from sqlalchemy.orm.session import make_transient


logger = logging.getLogger(__name__)


class ServerApiProc(ServerModule):
    """
    Server API processor
    """

    def __init__(self, *args, **kwargs):
        super(ServerApiProc, self).__init__(*args, **kwargs)

        self.trace_logger = Tracelogger(logger)
        self.local_data = threading.local()

    def init(self, server):
        """
        Initializes module with the server
        :param server:
        :return:
        """
        super(ServerApiProc, self).init(server=server)

    def run(self):
        """
        Kick off all running threads
        :return:
        """
        super(ServerApiProc, self).run()

    def load_active_requests(self, s, last_scan_margin=300, randomize=True):
        """
        Loads active API requests to process, from the oldest.
        After loading the result is a tuple (DbIpScanRecordUser, min_periodicity).

        :param s : SaQuery query
        :type s: SaQuery
        :param last_scan_margin: margin for filtering out records that were recently processed.
        :param randomize:
        :return:
        """
        q = s.query(DbApiWaitingObjects) \
            .join(DbApiKey, DbApiKey.id == DbApiWaitingObjects.api_key_id)\
            .filter(DbApiWaitingObjects.finished_at == None)\
            .filter(DbApiWaitingObjects.approval_status == 0)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, types.FloatType) else self.server.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1 * fact, fact))
            cur_margin = datetime.datetime.now() - datetime.timedelta(seconds=last_scan_margin)

            q = q.filter(salch.or_(
                DbApiWaitingObjects.last_scan_at < cur_margin,
                DbApiWaitingObjects.last_scan_at == None
            ))

        return q.group_by(DbApiWaitingObjects.id) \
            .order_by(DbApiWaitingObjects.last_scan_at)  # select the oldest scanned first

    def periodic_feeder(self, s):
        """
        Feed jobs for processing to the queue
        :param s:
        :return:
        """
        if self.server.periodic_queue_is_full():
            return

        try:
            min_scan_margin = self.server.min_scan_margin()
            query = self.load_active_requests(s, last_scan_margin=min_scan_margin)
            iterator = query.yield_per(100)
            for x in iterator:
                watch_target, min_periodicity, watch_service = x

                if self.server.periodic_queue_is_full():
                    return

                job = PeriodicApiProcessJob(target=watch_target, periodicity=min_periodicity)
                self.server.periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            s.rollback()
            logger.error('Exception loading watch jobs %s' % e)
            self.trace_logger.log(e)
            raise

    def process_periodic_job(self, job):
        """
        Process my jobs in the worker thread.
        :param job:
        :return:
        """
        if not isinstance(job, PeriodicApiProcessJob):
            return False

        logger.debug('Processing API job: %s, qsize: %s, sems: %s'
                     % (job, self.server.watcher_job_queue.qsize(), self.server.periodic_semaphores()))
        s = None
        url = None

        try:
            s = self.db.get_session()

            self.process_job_body(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.scan_ip_scan.is_failed():
                logger.info('Job failed, wildcard: %s' % (job.scan_ip_scan.is_failed()))
                job.attempts += 1
                job.success_scan = False

            else:
                job.success_scan = True

        except InvalidHostname as ih:
            logger.debug('Invalid host: %s' % url)
            job.success_scan = True  # TODO: back-off / disable, fatal error

        except Exception as e:
            logger.debug('Exception when processing the IP scan job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_close(s)

        return True

    def process_job_body(self, s, job):
        """
        Process the job - body. With session initialized, try-catch protected.
        :param s:
        :param job:
        :type job: PeriodicApiProcessJob
        :return:
        """
        target = job.target

        # CT test is performed only for cert tests
        if not target.object_type == 'cert':
            job.scan_ct_results.skip()

        # Job type multiplexing
        if target.object_type == 'cert':
            self.process_job_certificate(s, job)

        elif target.object_type == 'domain':
            self.process_job_domain(s, job)

        else:
            target.last_scan_status = 1
            target.finished_at = salch.func.now()
            target.approval_status = 2
            s.merge(target)

            raise ValueError('Unknown job type: %s' % target.object_type)

    def process_job_certificate(self, s, job):
        """
        Process certificate job
        :param s:
        :param job:
        :return:
        """
        # TODO: process certificate

    def process_job_domain(self, s, job):
        """
        Process domain job
        :param s:
        :param job:
        :return:
        """
        # TODO: process domain





