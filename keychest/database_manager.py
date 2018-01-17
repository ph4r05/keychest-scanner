#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Database manager
"""

from past.builtins import basestring  # pip install future
from past.builtins import cmp
from future.utils import iteritems

import json
import logging

from . import util, util_cert
from .trace_logger import Tracelogger


logger = logging.getLogger(__name__)


class DatabaseManager(object):
    """
    Base DB manager for certificate related tasks
    """

    def __init__(self):
        self.db = None
        self.config = None
        self.trace_logger = Tracelogger(logger)

    def init(self, **kwargs):
        """
        Initializes the Db manager
        :param kwargs:
        :return:
        """
        if 'db' in kwargs:
            self.db = kwargs.get('db')
        if 'config' in kwargs:
            self.config = kwargs.get('config')
        if 'trace_logger' in kwargs:
            self.trace_logger = kwargs.get('trace_logger')
