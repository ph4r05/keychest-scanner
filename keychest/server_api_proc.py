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

        # TODO: process the job in the worker
        return True




