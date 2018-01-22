#!/usr/bin/env python
# -*- coding: utf-8 -*-


import collections
import logging
import threading
import time

try:
    from UserDict import UserDict
    from UserDict import DictMixin
except ImportError:
    from collections import UserDict
    from collections import MutableMapping as DictMixin

from . import util
from threading import Semaphore as Semaphore
from .stat_sem import StatSemaphore
from .timed_semaphore import SemaphoreResult, TimedSemaphore


logger = logging.getLogger(__name__)
DEFAULT_EXPIRATION_TIME = 60*60


class SemaphoreRecord(object):
    """
    Record in the semaphore record
    """
    def __init__(self, sem):
        self.sem = sem
        self.last_use = None

    def touch(self):
        """
        Updates last use timer
        :return:
        """
        self.last_use = time.time()


class SemaphoreManager(object, DictMixin):
    """
    Managing associated semaphores.
    Mapping: sem_id -> semaphore

    """

    def __init__(self, default_count=1, default_factory=None):
        # Default dict factory.
        self.default_count = default_count
        self.default_factory = default_factory if default_factory else StatSemaphore(default_count)

        def factory():
            return SemaphoreRecord(self.default_factory())

        self.db = collections.defaultdict(factory)  # type: dict[string, SemaphoreRecord]
        self.db_lock = threading.RLock()

    def has_semaphore(self, key):
        """
        True if given semaphore is already in the manager
        :param key:
        :return:
        """
        with self.db_lock:
            return key in self.db

    def get(self, key, count=None, factory=None, timed=False):
        """
        Retrieves the semaphore from the register / creates a new one
        :param key:
        :param count:
        :param factory:
        :param timed:
        :return:
        :rtype: Semaphore
        """
        with self.db_lock:
            if key in self.db:
                rec = self.db[key]
                rec.touch()
                return rec.sem

            sem = None
            if factory:
                sem = factory()
            elif timed:
                sem = TimedSemaphore(count if count else self.default_count)
            elif count:
                sem = StatSemaphore(count)
            else:
                sem = self.default_factory()
            rec = SemaphoreRecord(sem)
            self.db[key] = rec
            return rec.sem

    def expire_semaphores(self):
        """
        Expires old semaphores
        :return:
        """
        with self.db_lock:
            cur_time = time.time()
            keys = list(self.db.keys())
            for key in keys:
                rec = self.db[key]
                if rec.last_use + DEFAULT_EXPIRATION_TIME >= cur_time:
                    continue

                logger.debug('Semaphore key expired: ' % key)

                if hasattr(rec.sem, 'countinv') and rec.sem.countinv() > 0:
                    logger.debug('Semaphore still in use, cannot destroy: %s' % key)
                    continue

                del self.db[key]

    def __getitem__(self, key):
        """
        Returns given semaphore / creates a new one with default factory
        :param key:
        :return:
        :rtype: Semaphore
        """
        with self.db_lock:
            return self.db[key].sem

    def __setitem__(self, key, value):
        """
        Sets the manager
        :param key:
        :param value:
        :return:
        """
        with self.db_lock:
            self.db[key] = value

    def __delitem__(self, key):
        """
        Deletes semaphore from the register. Should not be used.
        :param key:
        :return:
        """
        with self.db_lock:
            del self.db[key]

    def keys(self):
        """
        Keys
        :return:
        """
        with self.db_lock:
            return self.db.keys()



