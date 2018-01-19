#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging
import threading
import time

from . import util


logger = logging.getLogger(__name__)
DEFAULT_EXPIRATION_TIME = 60*60


class SemaphoreResult(object):
    """
    Returned by TimedSemaphore.acquire
    """
    def __init__(self, res, id=None, parent=None, time_locked=None):
        self.res = res  # type: bool
        self.id = id  # type: string
        self.parent = parent  # type: TimedSemaphore
        self.own_lock = threading.RLock()

        self._time_locked = None
        self.time_locked = time_locked  # type: int

        # Was released by expiration?
        self.was_released = False
        self.time_expire = None

    @property
    def time_locked(self):
        return self._time_locked

    @time_locked.setter
    def time_locked(self, t):
        if t is None:
            return
        self._time_locked = t
        self.time_expire = self.time_locked + DEFAULT_EXPIRATION_TIME

    def is_acquired(self):
        """
        Returns true if acquire has been successful
        :return:
        :rtype: bool
        """
        with self.own_lock:
            return self.res

    def release(self, quiet=False):
        """
        Releases this particular semaphore
        :param quiet
        :return:
        """
        with self.own_lock:
            if self.was_released:
                return

        if not self.is_acquired():
            if quiet:
                return
            else:
                raise ValueError('Semaphore not acquired')

        if not self.parent:
            if quiet:
                return
            else:
                raise ValueError('Parent not set')

        self.parent.release(self)
        self.was_released = True

    def expire(self):
        """
        Called by parent
        :return:
        """
        with self.own_lock:
            self.was_released = True

    def renew(self, extra_time=None):
        """
        Renews the time reservation for this lock
        :return:
        """
        with self.own_lock:
            if self.was_released:
                return False

            self.time_expire += extra_time if extra_time else DEFAULT_EXPIRATION_TIME
            return True

    def __enter__(self):
        pass

    def __exit__(self, t, v, tb):
        self.release(True)


class TimedSemaphore(object):
    """
    Timed semaphore manager
    Release one resource when timed out, enable to extend the timer (in case of crash), otherwise expires
    Usecase - only one certbot at given agent, only one Whois query per TLD.
    We want to recover from potential deadlocks.

    """
    def __init__(self, value=1, verbose=None):
        self.sem = threading.Semaphore(value, verbose=verbose)
        self.lock = threading.RLock()
        self.db = {}
        self._cur = value
        self._start_val = value

    def acquire(self, blocking=1):
        """Acquire a semaphore, decrementing the internal counter by one.

        When invoked without arguments: if the internal counter is larger than
        zero on entry, decrement it by one and return immediately. If it is zero
        on entry, block, waiting until some other thread has called release() to
        make it larger than zero. This is done with proper interlocking so that
        if multiple acquire() calls are blocked, release() will wake exactly one
        of them up. The implementation may pick one at random, so the order in
        which blocked threads are awakened should not be relied on. There is no
        return value in this case.

        When invoked with blocking set to true, do the same thing as when called
        without arguments, and return true.

        When invoked with blocking set to false, do not block. If a call without
        an argument would block, return false immediately; otherwise, do the
        same thing as when called without arguments, and return true.

        :param blocking:
        :return:
        :rtype: SemaphoreResult
        """

        # Check timetable and expire old semaphores
        self.expire_locks()

        # If blocking then timing does not work.
        # One more thread for timing cleanup would have to be created
        # The expire thread could be runned by this timed semaphore or by the common manager.
        ret = self.sem.acquire(blocking)
        res = SemaphoreResult(ret, parent=self)

        if blocking or ret:
            self._cur -= 1
            with self.lock:
                res.id = self._find_id()
                res.time_locked = time.time()
                self.db[res.id] = res

        return res

    def release(self, res):
        """Release a semaphore, incrementing the internal counter by one.

        When the counter is zero on entry and another thread is waiting for it
        to become larger than zero again, wake up that thread.

        Release without semaphore object should not be allowed, otherwise we don't
        know which object to release.

        :param res: SemaphoreResult to release in particular
        :type res: SemaphoreResult
        """
        if res is None:
            raise ValueError('SemaphoreResult is None')

        with self.lock:
            del self.db[res.id]

        if res.was_released:
            return

        self._cur += 1
        return self.sem.release()

    def expire_locks(self):
        """
        Called to expire old locks.
        If using blocking acquire this should be called by a separate expiring thread
        :return:
        """
        with self.lock:
            cur_time = time.time()
            ids = list(self.db.keys())
            for cur_id in ids:
                cur_lock = self.db[cur_id]  # type: SemaphoreResult
                if cur_lock.time_expire >= cur_time:
                    continue

                cur_lock.expire()
                self.release(cur_lock)
                logger.warning('Timed semaphore expired: %s' % cur_id)

    def count(self):
        """
        Currently available semaphores to acquire
        :return:
        """
        return self._cur

    def countinv(self):
        """
        Currently occupied semaphores (to release)
        :return:
        """
        return self._start_val - self._cur

    def _find_id(self):
        """
        Finds unique id (not yet in db)
        Has to be done under lock
        :return:
        """
        is_uniq = False
        cur_id = None

        while is_uniq:
            cur_id = util.random_alphanum(24)
            is_uniq = cur_id not in self.db
        return cur_id

    def __enter__(self):
        return self.acquire()

    def __exit__(self, t, v, tb):
        self.release(None)

