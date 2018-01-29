#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key management utils
"""

from past.builtins import basestring    # pip install future
from past.builtins import cmp
from future.utils import iteritems

from . import util
from .dbutil import DbHostGroup, DbManagedSolution, DbManagedService, DbManagedHost, DbManagedTest, \
    DbManagedTestProfile, DbManagedCertIssue, DbManagedServiceToGroupAssoc, DbManagedSolutionToServiceAssoc, \
    DbKeychestAgent, DbManagedCertificate, Certificate, DbWatchTarget, DbDnsResolve, DbHandshakeScanJob, DbOwner,\
    DbManagedCertChain, DbManagedPrivate, DbHelper

from .util_keychest import Encryptor
from .stat_sem import SemaphoreWrapper
from .semaphore_manager import SemaphoreManager

import json
import logging


logger = logging.getLogger(__name__)


class ManagementUtils(object):
    """
    Management utils
    """

    def __init__(self, **kwargs):
        pass

    @staticmethod
    def get_service_domains(svc):
        """
        Returns list of domains for the service
        :param svc:
        :type svc: DbManagedService
        :return:
        """
        domains = [svc.svc_name]
        if svc.svc_aux_names:
            domains += json.loads(svc.svc_aux_names)
        return domains

