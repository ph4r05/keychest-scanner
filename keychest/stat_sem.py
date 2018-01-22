#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
from threading import Semaphore as Semaphore


def is_py3():
    """
    Returns true if running in py3
    :return:
    """
    return sys.version_info > (3, 0)


class SemaphoreWrapper(object):
    """
    Simple wrapper for easy non-blocking acquire
    """
    def __init__(self, sem=None, blocking=1, timeout=None, **kwargs):
        """
        Sem wrapper obj
        :param sem:
        :type sem: Semaphore
        :param blocking:
        :param timeout:
        :param kwargs:
        """
        self.sem = sem  # type: Semaphore
        self.blocking = blocking
        self.timeout = timeout
        self._acquired = False

    @property
    def acquired(self):
        """
        Returns acquire state of the lock
        :return:
        """
        return self._acquired

    @classmethod
    def acquire_sem(cls, sem, blocking=1, timeout=None, **kwargs):
        """
        Acquire semaphore with context manager
        :param sem:
        :type sem: Semaphore
        :param blocking:
        :return:
        """
        wrap = cls(sem=sem, **kwargs)
        wrap.acquire(blocking=blocking, timeout=timeout)
        return wrap

    def acquire(self, blocking=None, timeout=None, **kwargs):
        """
        Acquire wrapper semaphore
        :param blocking:
        :param timeout:
        :param kwargs:
        :return:
        """
        blocking = blocking if blocking is not None else self.blocking
        timeout = timeout if timeout is not None else self.timeout

        kw = {'timeout': timeout} if is_py3() else {}
        self._acquired = self.sem.acquire(blocking=blocking, **kw)
        if blocking:
            self._acquired = True
        return self._acquired

    def release(self):
        """
        Releases wrapped lock
        :return:
        """
        if self._acquired:
            self.sem.release()
            self._acquired = False

    def __enter__(self):
        """
        Context manager enter - instance based acquire
        :return:
        """
        return self.acquire()

    def __exit__(self, t, v, tb):
        self.release()


class BaseStatSemaphore(object):
    """
    Simple semaphore wrapper with stat counting - base class
    """
    def __init__(self, value=1, verbose=None, **kwargs):
        """

        :param value:
        :param verbose:
        :param kwargs:
        """
        self.sem = Semaphore(value, verbose=verbose)  # type: Semaphore
        self._cur = value
        self._start_val = value

    def count(self):
        """
        Number of free locks
        :return:
        """
        return self._cur

    def countinv(self):
        """
        Number of used locks
        :return:
        """
        return self._start_val - self._cur


class StatSemaphore(BaseStatSemaphore):
    """
    Simple semaphore wrapper with stat counting
    """
    def __init__(self, value=1, verbose=None, **kwargs):
        super(StatSemaphore, self).__init__(value, verbose, **kwargs)

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
        """
        ret = self.sem.acquire(blocking)
        if blocking or ret:
            self._cur -= 1
        return ret

    def release(self):
        """Release a semaphore, incrementing the internal counter by one.

        When the counter is zero on entry and another thread is waiting for it
        to become larger than zero again, wake up that thread.

        """
        self._cur += 1
        return self.sem.release()

    def __enter__(self):
        self.acquire()

    def __exit__(self, t, v, tb):
        self.release()

