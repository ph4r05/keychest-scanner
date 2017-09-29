#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API processor module.

Processes API requests to insert / add the object.
e.g. request of the user to add a certificate to the monitoring send by public API on KC.

"""

from past.builtins import cmp
from future.utils import iteritems

import util
from config import Config
from redis_queue import RedisQueue
import redis_helper as rh
from trace_logger import Tracelogger
from errors import Error, InvalidHostname, ServerShuttingDown, InvalidInputData
from server_jobs import JobTypes, BaseJob, PeriodicJob, ScanResults, PeriodicApiProcessJob
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, CrtshInputType, DbLastScanCacheType, IpType
from server_module import ServerModule
from dbutil import DbApiWaitingObjects, DbApiKey, Certificate, CertificateAltName, DbHelper
from crt_sh_processor import CrtShTimeoutException, CrtShException

import time
import json
import math
import random
import datetime
import types
import logging
import threading
import collections
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue


import sqlalchemy as salch
from sqlalchemy.orm.query import Query as SaQuery
from sqlalchemy import case, literal_column
from sqlalchemy.orm.session import make_transient


logger = logging.getLogger(__name__)


class ServerApiProc(ServerModule):
    """
    Server API processor
    """

    def __init__(self, *args, **kwargs):
        super(ServerApiProc, self).__init__(*args, **kwargs)

        self.trace_logger = Tracelogger(logger)
        self.local_data = threading.local()

        self.delta_ct_scan = datetime.timedelta(hours=6)

    def init(self, server):
        """
        Initializes module with the server
        :param server:
        :return:
        """
        super(ServerApiProc, self).init(server=server)

    def run(self):
        """
        Kick off all running threads
        :return:
        """
        super(ServerApiProc, self).run()

    def load_active_requests(self, s, last_scan_margin=300, randomize=True):
        """
        Loads active API requests to process, from the oldest.
        After loading the result is a tuple (DbIpScanRecordUser, min_periodicity).

        :param s : SaQuery query
        :type s: SaQuery
        :param last_scan_margin: margin for filtering out records that were recently processed.
        :param randomize:
        :return:
        """
        q = s.query(DbApiWaitingObjects) \
            .join(DbApiKey, DbApiKey.id == DbApiWaitingObjects.api_key_id)\
            .filter(DbApiWaitingObjects.finished_at == None)\
            .filter(DbApiWaitingObjects.approval_status == 0)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, types.FloatType) else self.server.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1 * fact, fact))
            cur_margin = datetime.datetime.now() - datetime.timedelta(seconds=last_scan_margin)

            q = q.filter(salch.or_(
                DbApiWaitingObjects.last_scan_at < cur_margin,
                DbApiWaitingObjects.last_scan_at == None
            ))

        return q.group_by(DbApiWaitingObjects.id) \
            .order_by(DbApiWaitingObjects.last_scan_at)  # select the oldest scanned first

    def periodic_feeder(self, s):
        """
        Feed jobs for processing to the queue
        :param s:
        :return:
        """
        if self.server.periodic_queue_is_full():
            return

        try:
            min_scan_margin = self.server.min_scan_margin()
            query = self.load_active_requests(s, last_scan_margin=min_scan_margin)
            iterator = query.yield_per(100)
            for x in iterator:
                watch_target, min_periodicity, watch_service = x

                if self.server.periodic_queue_is_full():
                    return

                job = PeriodicApiProcessJob(target=watch_target, periodicity=min_periodicity)
                self.server.periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            s.rollback()
            logger.error('Exception loading watch jobs %s' % e)
            self.trace_logger.log(e)
            raise

    def periodic_job_update_last_scan(self, job):
        """
        Update last stan of the job
        :param job:
        :return: True if job was consumed
        """
        if not isinstance(job, PeriodicApiProcessJob):
            return False

        s = self.db.get_session()
        try:
            stmt = DbApiWaitingObjects.__table__.update() \
                .where(DbApiWaitingObjects.id == job.target.id) \
                .values(last_scan_at=salch.func.now())
            s.execute(stmt)
            s.commit()

        finally:
            util.silent_close(s)

        return True

    def finish_waiting_object(self, s, target, **kwargs):
        """
        Finishes waiting object, updates database so it is not considered as active anymore
        :param target:
        :type target: DbApiWaitingObjects
        :param kwargs:
        :return:
        """
        target.finished_at = salch.func.now()
        for key, value in iteritems(kwargs):
            setattr(target, key, value)

        return s.merge(target)

    def process_periodic_job(self, job):
        """
        Process my jobs in the worker thread.
        :param job:
        :type job: PeriodicApiProcessJob
        :return:
        """
        if not isinstance(job, PeriodicApiProcessJob):
            return False

        logger.debug('Processing API job: %s, qsize: %s, sems: %s'
                     % (job, self.server.watcher_job_queue.qsize(), self.server.periodic_semaphores()))

        s = None
        try:
            s = self.db.get_session()

            self.process_job_body(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.scan_ip_scan.is_failed():
                logger.info('Job failed, wildcard: %s' % (job.scan_ip_scan.is_failed()))
                job.attempts += 1
                job.success_scan = False

            else:
                job.success_scan = True

        except InvalidInputData as id:
            logger.debug('Invalid test input')
            job.success_scan = True  # job is deemed processed
            self.finish_waiting_object(s, job.target, last_scan_status=-1)

        except InvalidHostname as ih:
            logger.debug('Invalid host')
            job.success_scan = True  # TODO: back-off / disable, fatal error
            self.finish_waiting_object(s, job.target, last_scan_status=-2)

        except Exception as e:
            logger.debug('Exception when processing the IP scan job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_close(s)

        return True

    def process_job_body(self, s, job):
        """
        Process the job - body. With session initialized, try-catch protected.
        :param s:
        :param job:
        :type job: PeriodicApiProcessJob
        :return:
        """
        target = job.target

        # CT test is performed only for cert tests
        if not target.object_type == 'cert':
            job.scan_ct_results.skip()

        # Job type multiplexing
        if target.object_type == 'cert':
            self.process_job_certificate(s, job)

        elif target.object_type == 'domain':
            self.process_job_domain(s, job)

        else:
            target.last_scan_status = -4
            target.finished_at = salch.func.now()
            target.approval_status = 2
            s.merge(target)

            raise ValueError('Unknown job type: %s' % target.object_type)

    def process_job_certificate(self, s, job):
        """
        Process certificate job
        :param s:
        :param job:
        :type job: PeriodicApiProcessJob
        :return:
        """
        target = job.target

        # Is CT scan applicable?
        if target.last_scan_at and target.last_scan_at > self.server.diff_time(self.delta_ct_scan, rnd=True):
            job.scan_ct_results.skip()
            return  # scan is relevant enough

        try:
            self.process_certificate_job_body(s, job)

        except Exception as e:
            job.scan_ct_results.fail()

            logger.error('API certificate exception: %s' % e)
            self.trace_logger.log(e, custom_msg='API certificate processing')

    def process_certificate_job_body(self, s, job):
        """
        Processing the cert
        :param s:
        :param job:
        :return:
        """
        target = job.target
        cert_db = None

        # Cert processing if not already
        if target.processed_at is None:
            cert_db = self.process_certificate(s, job)
            target.processed_at = salch.func.now()
            s.merge(target)
            s.commit()

        else:
            cert_db = self.server.cert_load_by_id(s, target.certificate_id)

        # CT scan
        scan_kwargs = dict()
        scan_kwargs['timeout'] = 10
        scan_kwargs['sha256'] = cert_db.fprint_sha256
        try:
            crt_sh = self.server.crt_sh_proc.query(None, **scan_kwargs)

        except CrtShTimeoutException as tex:
            logger.warning('CRTSH timeout for: %s' % cert_db.fprint_sha256)
            raise

        if crt_sh is None:
            raise CrtShException('CRTSH returned empty result for %s' % cert_db.fprint_sha256)

        target.last_scan_at = salch.func.now()
        target.last_scan_status = 1
        target.ct_found_at = salch.func.now()

        # Check if certificate is in the CT
        if crt_sh.result is not None and util.lower(crt_sh.result.sha256) == util.lower(cert_db.fprint_sha256):
            self.add_to_monitoring(s, job, cert_db)
            self.finish_waiting_object(s, target)
        s.commit()

    def add_to_monitoring(self, s, job, cert_db):
        """
        Adds all hosts to the monitoring.
        :param s:
        :param job:
        :param cert_db:
        :return:
        """
        domains = cert_db.all_names
        api_key = s.query(DbApiKey).filter(DbApiKey.id == job.target.api_key_id).first()

        self.server.auto_fill_new_watches_body(user_id=api_key.user_id,
                                               domain_names=domains,
                                               default_new_watches=dict())

    def process_certificate(self, s, job):
        """
        Process certificate, return cert ID
        Parsing the cert, filling in cert structure.
        :param s:
        :param job:
        :type job: PeriodicApiProcessJob
        :return:
        :rtype: Certificate
        """
        pem = job.target.certificate
        cert_db = Certificate()
        cert_db.created_at = salch.func.now()
        cert_db.pem = util.strip_pem(pem)
        cert_db.source = 'api'

        try:
            x509_cert = self.server.parse_certificate(cert_db, pem=str(cert_db.pem))

        except Exception as e:
            logger.error('Unable to parse API certificate job id %s: %s' % (job.target.id, e))
            self.trace_logger.log(e)
            raise InvalidInputData('Certificate invalid')

        new_cert = cert_db
        cert_db, is_new = self.server.add_cert_or_fetch(s, cert_db, fetch_first=True, add_alts=True)

        # Cert exists, fill in missing fields if empty
        if not is_new:
            mm = Certificate
            changes = DbHelper.update_model_null_values(cert_db, new_cert, [mm.key_type, mm.key_bit_size, mm.sig_alg])
            if changes > 0:
                s.commit()
        else:
            s.commit()

        # Associate
        job.target.certificate_id = cert_db.id
        return cert_db

    def process_job_domain(self, s, job):
        """
        Process domain job
        :param s:
        :param job:
        :type job: PeriodicApiProcessJob
        :return:
        """
        # Domain processing is not defined yet.
        # Waiting for API key approval, if not approval, switch to approval state
        # For now this request is rejected
        # TODO: implement add domain logic
        target = job.target
        target.last_scan_status = 1
        target.finished_at = salch.func.now()
        target.approval_status = 2
        s.merge(target)






