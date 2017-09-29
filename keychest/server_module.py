#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Basic server module skeleton
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

import time
import json
import logging
import threading
import collections
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue


logger = logging.getLogger(__name__)


class ServerModule(object):
    """
    Server module
    """

    def __init__(self, *args, **kwargs):
        self.server = None
        self.db = None
        self.config = None
        self.trace_logger = Tracelogger(logger)

    def init(self, server):
        """
        Initializes module with the server
        :param server:
        :return:
        """
        self.server = server
        self.db = server.db
        self.config = server.config

    def shutdown(self):
        """
        Shutdown operation
        :return:
        """
        pass

    def is_running(self):
        """
        Returns true if server is still running
        :return:
        """
        return self.server.is_running()

    def run(self):
        """
        Kick off all running threads
        :return:
        """

