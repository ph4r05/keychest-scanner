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
from .stat_sem import StatSemaphore
from .timed_semaphore import SemaphoreResult, TimedSemaphore


logger = logging.getLogger(__name__)
DEFAULT_EXPIRATION_TIME = 60*60


class SemaphoreManager(object, DictMixin):
    """
    Managing associated semaphores.
    Mapping: sem_id -> semaphore

    """

    def __init__(self, default_count=1, default_factory=None):
        self.db = collections.defaultdict(default_factory if default_factory else lambda: StatSemaphore(default_count))
        self.db_lock = threading.RLock()

    def has_semaphore(self, key):
        """

        :param key:
        :return:
        """
        with self.db_lock:
            return key in self.db

    def expire_semaphores(self):
        """
        Expires old semaphores
        :return:
        """
        pass

    def __getitem__(self, key):
        """

        :param key:
        :return:
        """
        pass

    def __setitem__(self, key, value):
        """

        :param key:
        :param value:
        :return:
        """
        raise KeyError

    def __delitem__(self, key):
        """

        :param key:
        :return:
        """
        raise KeyError

    def keys(self):
        """
        Keys
        :return:
        """
        with self.db_lock:
            return self.db.keys()



