#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging
import sys
import traceback
import hashlib


logger = logging.getLogger(__name__)


def error_message(e, message=None, cause=None):
    """
    Formats exception message + cause
    :param e:
    :param message:
    :param cause:
    :return: formatted message, includes cause if any is set
    """
    if message is None and cause is None:
        return None
    elif message is None:
        return '%s, caused by %r' % (e.__class__, cause)
    elif cause is None:
        return message
    else:
        return '%s, caused by %r' % (message, cause)


class Tracelogger(object):
    """
    Prints traceback to the debugging logger if not shown before
    """

    def __init__(self, logger=None):
        self.logger = logger
        self._db = set()

    def log(self, cause=None, do_message=True, custom_msg=None):
        """
        Loads exception data from the current exception frame - should be called inside the except block
        :return:
        """
        message = error_message(self, cause=cause)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback_formatted = traceback.format_exc()
        traceback_val = traceback.extract_tb(exc_traceback)

        md5 = hashlib.md5(traceback_formatted).hexdigest()

        if md5 in self._db:
            # self.logger.debug('Exception trace logged: %s' % md5)
            return

        if custom_msg is not None and cause is not None:
            self.logger.debug('%s : %s' % (custom_msg, cause))
        elif custom_msg is not None:
            self.logger.debug(custom_msg)
        elif cause is not None:
            self.logger.debug('%s' % cause)

        self.logger.debug(traceback_formatted)
        self._db.add(md5)


