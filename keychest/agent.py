#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Monitoring Agent
"""

import time
from past.builtins import cmp


class AgentResultPush(object):
    def __init__(self):
        self.old_scan = None
        self.new_scan = None
        self.job = None
        self.added_at = time.time()

    def cmpval(self):
        """
        Returns tuple for comparison
        :return:
        """
        return self.added_at

    def __cmp__(self, other):
        """
        Compare operation for priority queue.
        :param other:
        :type other: AgentResultPush
        :return:
        """
        return cmp(self.cmpval(), other.cmpval())

    def to_json(self):
        return {}

    def __repr__(self):
        return '<AgentResultPush(added_at=%r, new_scan=%r, job=%r)>' % (self.added_at, self.new_scan, self.job)

