#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Server job classes
"""

from past.builtins import cmp
import collections
from .tls_domain_tools import TargetUrl
from .dbutil import DbWatchService, DbWatchTarget, DbIpScanRecord, DbApiWaitingObjects, DbManagedTest, \
    DbManagedSolution, DbManagedService, DbManagedHost, DbManagedTestProfile, DbKeychestAgent, DbManagedCertIssue, \
    DbManagedCertificate, Certificate


class ScanResults(object):
    """
    Generic scan result (tls, CT, whois)
    """
    def __init__(self, success=False, code=None, aux=None):
        self.success = success
        self.skipped = False  # if skipped test was not performed
        self.code = code
        self.attempts = 0
        self.aux = aux

    def fail(self):
        self.skipped = False
        self.success = False
        self.attempts += 1

    def ok(self):
        self.skipped = False
        self.success = True

    def skip(self, aux=0xdeadbeef):
        self.skipped = True
        if aux != 0xdeadbeef:
            self.aux = aux

    def is_failed(self):
        return not self.success and not self.skipped

    def is_skipped(self):
        return self.skipped

    def __repr__(self):
        return '<ScanResults(success=%r, skipped=%r, code=%r, attempts=%r, aux=%r)>' \
               % (self.success, self.skipped, self.code, self.attempts, self.aux)


class JobTypes(object):
    """
    Job types used to process by Keychest workers
    """
    TARGET = 1  # periodic spotcheck
    SUB = 2  # sub-domain scanning (CT)
    UI = 3  # UI initiated scan
    IP_SCAN = 4  # IPv4 scanning to detect running hosts
    API_PROC = 5  # API requests processing
    MGMT_TEST = 6  # Management testing
    MGMT_RENEW = 7  # Management renewal
    MGMT_CERT_CHECK = 8  # Management cert check

    def __init__(self):
        pass


class BaseJob(object):
    """
    Base periodic job class
    """
    def __init__(self, type=None, *args, **kwargs):
        """
        :param type:
        :param args:
        :param kwargs:
        """
        self.type = type
        self.attempts = 0
        self.later = 0
        self.success_scan = False

    def reset_later(self):
        """
        Resets later counter
        :return:
        """
        self.later = 0

    def inclater(self):
        """
        Increments later counter for priority counting
        :return:
        """
        self.later += 1

    def key(self):
        """
        Returns hashable key for the job dbs
        :return:
        """
        return None

    def cmpval(self):
        """
        Returns tuple for comparison
        :return:
        """
        return self.attempts, self.later

    def __cmp__(self, other):
        """
        Compare operation for priority queue.
        :param other:
        :type other: BaseJob
        :return:
        """
        return cmp(self.cmpval(), other.cmpval())

    def to_json(self):
        js = collections.OrderedDict()
        return js

    def on_run(self):
        pass

    def on_fail(self):
        pass

    def on_readd(self):
        pass

    def on_remove(self):
        pass

    def __repr__(self):
        return '<BaseJob(type=%r, attempts=%r, later=%r)>' % (self.type, self.attempts, self.later)


class RedisJob(BaseJob):
    """
    UI invoked redis queued job
    """
    def __init__(self, target=None, periodicity=None, watch_service=None, type=None, *args, **kwargs):
        """
        :param target:
        :type target: DbWatchTarget
        :param periodicity:
        :param watch_service:
        :type watch_service: DbWatchService
        :param args:
        :param kwargs:
        """
        super(RedisJob, self).__init__(type=JobTypes.UI)

        self.target = target  # type: DbWatchTarget
        self.service = watch_service  # type: DbWatchService

        self.primary_ip = None
        self.ips = []
        self.scan_dns = ScanResults()
        self.scan_tls = ScanResults()
        self.scan_crtsh = ScanResults()
        self.scan_whois = ScanResults()

    def key(self):
        return 'u%s' % self.target.id

    def cmpval(self):
        return self.attempts, \
               self.later

    def url(self):
        """
        Returns url object from the target
        :return:
        """
        return TargetUrl(scheme=self.target.scan_scheme, host=self.target.scan_host, port=self.target.scan_port)

    def watch_id(self):
        """
        Returns watch target id
        :return:
        """
        return self.target.id

    def __repr__(self):
        return '<RedisJob(target=<WatcherTarget(id=%r, host=%r, self=%r)>, attempts=%r, last_scan_at=%r)>' \
               % (self.target.id, self.target.scan_host, self.target, self.attempts, self.target.last_scan_at)


class PeriodicJob(BaseJob):
    """
    Represents periodic job loaded from the db
    """

    def __init__(self, target=None, periodicity=None, watch_service=None, type=None, *args, **kwargs):
        """
        :param target:
        :type target: DbWatchTarget
        :param periodicity:
        :param watch_service:
        :type watch_service: DbWatchService
        :param args:
        :param kwargs:
        """
        super(PeriodicJob, self).__init__(type=JobTypes.TARGET)

        self.target = target  # type: DbWatchTarget
        self.periodicity = periodicity
        self.service = watch_service  # type: DbWatchService

        self.primary_ip = None
        self.ips = []
        self.scan_dns = ScanResults()
        self.scan_tls = ScanResults()
        self.scan_crtsh = ScanResults()
        self.scan_whois = ScanResults()

    def key(self):
        return 'w%s' % self.target.id

    def cmpval(self):
        return self.attempts, \
               self.later, \
               self.target.last_scan_at is None, \
               self.target.last_scan_at

    def url(self):
        """
        Returns url object from the target
        :return:
        """
        return TargetUrl(scheme=self.target.scan_scheme, host=self.target.scan_host, port=self.target.scan_port)

    def watch_id(self):
        """
        Returns watch target id
        :return:
        """
        return self.target.id

    def __repr__(self):
        return '<PeriodicJob(target=<WatcherTarget(id=%r, host=%r, self=%r)>, attempts=%r, last_scan_at=%r)>' \
               % (self.target.id, self.target.scan_host, self.target, self.attempts, self.target.last_scan_at)


class PeriodicReconJob(BaseJob):
    """
    Represents periodic job loaded from the db - recon
    """

    def __init__(self, target=None, periodicity=None, type=None, *args, **kwargs):
        """
        :param target:
        :type target: DbSubdomainWatchTarget
        :param args:
        :param kwargs:
        """
        super(PeriodicReconJob, self).__init__(type=JobTypes.SUB)

        self.target = target
        self.periodicity = periodicity
        self.scan_crtsh_wildcard = ScanResults()

    def key(self):
        return 'r%s' % self.target.id

    def cmpval(self):
        return self.attempts, \
               self.later, \
               self.target.last_scan_at is None, \
               self.target.last_scan_at

    def watch_id(self):
        """
        Returns watch target id
        :return:
        """
        return self.target.id

    def __repr__(self):
        return '<PeriodicReconJob(target=<DbSubdomainWatchTarget(id=%r, host=%r, self=%r)>, attempts=%r, later=%r,' \
               'last_scan_at=%r)>' \
               % (self.target.id, self.target.scan_host, self.target, self.attempts, self.later,
                  self.target.last_scan_at)


class PeriodicIpScanJob(BaseJob):
    """
    Represents periodic job loaded from the db - ip scanning
    """

    def __init__(self, target=None, periodicity=None, type=None, *args, **kwargs):
        """
        :param target:
        :type target: DbIpScanRecord
        :param args:
        :param kwargs:
        """
        super(PeriodicIpScanJob, self).__init__(type=JobTypes.IP_SCAN)

        self.target = target
        self.periodicity = periodicity
        self.scan_ip_scan = ScanResults()

    def key(self):
        return 'ip_%s' % self.target.id

    def cmpval(self):
        return self.attempts, \
               self.later, \
               self.target.last_scan_at is None, \
               self.target.last_scan_at

    def record_id(self):
        """
        Returns watch target id
        :return:
        """
        return self.target.id

    def __repr__(self):
        return '<PeriodicIpScanJob(target=<DbIpScanRecord(id=%r, start=%r, end=%r, self=%r)>, attempts=%r, later=%r,' \
               'last_scan_at=%r)>' \
               % (self.target.id, self.target.ip_beg, self.target.ip_end, self.target, self.attempts, self.later,
                  self.target.last_scan_at)


class PeriodicApiProcessJob(BaseJob):
    """
    Represents periodic job loaded from the db - enqueued by API client
    """

    def __init__(self, target=None, periodicity=None, type=None, *args, **kwargs):
        """
        :param target:
        :type target: DbApiWaitingObjects
        :param args:
        :param kwargs:
        """
        super(PeriodicApiProcessJob, self).__init__(type=JobTypes.API_PROC)

        self.target = target
        self.periodicity = periodicity
        self.scan_ct_results = ScanResults()

    def key(self):
        return 'api_%s' % self.target.id

    def cmpval(self):
        return self.attempts, \
               self.later, \
               self.target.processed_at is None, \
               self.target.processed_at, \
               self.target.last_scan_at is None, \
               self.target.last_scan_at

    def record_id(self):
        """
        Returns watch target id
        :return:
        """
        return self.target.id

    def __repr__(self):
        return '<PeriodicApiProcessJob(target=<DbApiWaitingObjects(id=%r, self=%r)>, attempts=%r, later=%r,' \
               'processed_at=%r, last_scan_at=%r)>' \
               % (self.target.id, self.target, self.attempts, self.later,
                  self.target.processed_at, self.target.last_scan_at)


class PeriodicMgmtCertCheckJob(BaseJob):
    """
    Job for managed certificate fetch & check.
    Used if certificate is loaded by API, from the remote file system or a different non-local
    non-direct method.
    """

    def __init__(self, *args, **kwargs):
        super(PeriodicMgmtCertCheckJob, self).__init__(type=JobTypes.MGMT_CERT_CHECK)
        self.service = kwargs.get('service')

    def key(self):
        return 'mgmt_cert_check_%s' % self.service.id

    def cmpval(self):
        return self.attempts, \
               self.later, \
               self.service.id


class PeriodicMgmtRenewalJob(BaseJob):
    """
    Check if the renewal for the managed service is not needed, performs the renewal
    """

    def __init__(self, target=None, *args, **kwargs):
        """
        :param target:
        :type target: DbManagedService
        :param args:
        :param kwargs:
        """
        super(PeriodicMgmtRenewalJob, self).__init__(type=JobTypes.MGMT_RENEW)

        self.target = target  # type: DbManagedService
        self.solution = kwargs.get('solution')  # type: DbManagedSolution
        self.test_profile = kwargs.get('test_profile')  # type: DbManagedTestProfile
        self.agent = kwargs.get('agent')  # type: DbKeychestAgent
        self.managed_certificate = kwargs.get('managed_certificate')  # type: DbManagedCertificate
        self.certificate = kwargs.get('certificate')  # type: Certificate

        self.results = ScanResults()

    def key(self):
        return 'mgmt_renew_%s' % self.target.id

    def cmpval(self):
        return self.attempts, \
               self.later, \
               self.target.id

    def record_id(self):
        """
        Returns watch target id
        :return:
        """
        return self.target.id

    def __repr__(self):
        return '<PeriodicMgmtRenewalJob(target=<DbManagedService(id=%r, self=%r)>, attempts=%r, later=%r,' \
               'svc_name=%r)>' \
               % (self.target.id, self.target, self.attempts, self.later,
                  self.target.svc_name)


class PeriodicMgmtTestJob(BaseJob):
    """
    Represents periodic job loaded from the db for managed service testing
    """

    def __init__(self, target=None, type=None, *args, **kwargs):
        """
        :param target:
        :type target: DbManagedTest
        :param args:
        :param kwargs:
        """
        super(PeriodicMgmtTestJob, self).__init__(type=JobTypes.MGMT_TEST)

        self.target = target  # type: DbManagedTest
        self.solution = kwargs.get('solution')  # type: DbManagedSolution
        self.service = kwargs.get('service')  # type: DbManagedService
        self.host = kwargs.get('host')  # type: DbManagedHost
        self.test_profile = kwargs.get('test_profile')  # type: DbManagedTestProfile
        self.agent = kwargs.get('agent')  # type: DbKeychestAgent

        self.scan_test_results = ScanResults()

    def key(self):
        return 'mgmt_test_%s' % self.target.id

    def cmpval(self):
        return self.attempts, \
               self.later, \
               self.target.last_scan_at is None, \
               self.target.last_scan_at

    def record_id(self):
        """
        Returns watch target id
        :return:
        """
        return self.target.id

    def __repr__(self):
        return '<PeriodicMgmtTestJob(target=<DbManagedTest(id=%r, self=%r)>, attempts=%r, later=%r,' \
               'host_id=%r, last_scan_at=%r)>' \
               % (self.target.id, self.target, self.attempts, self.later,
                  self.target.host_id, self.target.last_scan_at)
