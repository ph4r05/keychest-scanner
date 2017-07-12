#!/usr/bin/env python
# -*- coding: utf-8 -*-


import threading


class StatSemaphore(object):
    """
    Simple semaphore wrapper with stat counting
    """
    def __init__(self, value=1, verbose=None):
        self.sem = threading.Semaphore(value, verbose=verbose)
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

    def count(self):
        return self._cur

    def countinv(self):
        return self._start_val - self._cur

    def __enter__(self):
        self.acquire()

    def __exit__(self, t, v, tb):
        self.release()

