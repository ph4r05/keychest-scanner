#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Server part of the script
"""

from past.builtins import cmp

from daemon import Daemon
from core import Core
from config import Config
from dbutil import MySQL, ScanJob, Certificate, CertificateAltName, DbCrtShQuery, DbCrtShQueryResult, \
    DbHandshakeScanJob, DbHandshakeScanJobResult, DbWatchTarget, DbWatchAssoc, DbBaseDomain, DbWhoisCheck, \
    DbScanGaps, DbScanHistory, DbUser, DbLastRecordCache, DbSystemLastEvents, DbHelper, ColTransformWrapper, \
    DbDnsResolve
import dbutil

from redis_client import RedisClient
from redis_queue import RedisQueue
import redis_helper as rh
from trace_logger import Tracelogger
from tls_handshake import TlsHandshaker, TlsHandshakeResult, TlsIncomplete, TlsTimeout, TlsException, TlsHandshakeErrors
from cert_path_validator import PathValidator, ValidationException
from tls_domain_tools import TlsDomainTools, TargetUrl
from tls_scanner import TlsScanner, TlsScanResult, RequestErrorCode, RequestErrorWrapper
from errors import Error

import threading
import pid
import socket
import time
import re
import os
import sys
import types
import util
import json
import base64
import itertools
import argparse
import calendar
from threading import RLock as RLock
import logging
import coloredlogs
import traceback
import collections
import signal
from queue import Queue, Empty as QEmpty, PriorityQueue
from datetime import datetime, timedelta

import sqlalchemy as salch
from sqlalchemy.orm.query import Query as SaQuery
from sqlalchemy import case, literal_column

from crt_sh_processor import CrtProcessor, CrtShIndexRecord, CrtShIndexResponse
import ph4whois


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class AppDeamon(Daemon):
    """
    Daemon wrapper
    """
    def __init__(self, *args, **kwargs):
        Daemon.__init__(self, *args, **kwargs)
        self.app = kwargs.get('app')

    def run(self, *args, **kwargs):
        self.app.work()


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

    def __repr__(self):
        return '<ScanResults(success=%r, skipped=%r, code=%r, attempts=%r, aux=%r)>' \
               % (self.success, self.skipped, self.code, self.attempts, self.aux)


class PeriodicJob(object):
    """
    Represents periodic job loaded from the db
    """
    def __init__(self, target=None, periodicity=None, *args, **kwargs):
        """
        :param target:
        :type target: DbWatchTarget
        :param args:
        :param kwargs:
        """
        self.target = target
        self.periodicity = periodicity
        self.success_scan = False
        self.attempts = 0

        self.primary_ip = None
        self.scan_dns = ScanResults()
        self.scan_tls = ScanResults()
        self.scan_crtsh = ScanResults()
        self.scan_whois = ScanResults()

    def key(self):
        """
        Returns hashable key for the job dbs
        :return:
        """
        return self.target.id

    def cmpval(self):
        """
        Returns tuple for comparison
        :return:
        """
        return self.attempts, \
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

    def __cmp__(self, other):
        """
        Compare operation for priority queue.
        :param other:
        :type other: PeriodicJob
        :return:
        """
        return cmp(self.cmpval(), other.cmpval())

    def to_json(self):
        js = collections.OrderedDict()
        return js

    def __repr__(self):
        return '<PeriodicJob(target=<WatcherTarget(id=%r, host=%r, self=%r)>, attempts=%r, last_scan_at=%r)>' \
               % (self.target.id, self.target.scan_host, self.target, self.attempts, self.target.last_scan_at)


class Server(object):
    """
    Main server object
    """

    def __init__(self, *args, **kwargs):
        self.core = Core()
        self.args = None
        self.config = None

        self.logdir = '/var/log/enigma-keychest'
        self.piddir = '/var/run'

        self.daemon = None
        self.running = True
        self.run_thread = None
        self.stop_event = threading.Event()
        self.terminate = False

        self.db = None
        self.redis = None
        self.redis_queue = None

        self.job_queue = Queue(50)
        self.local_data = threading.local()
        self.workers = []

        self.watch_last_db_scan = 0
        self.watch_db_scan_period = 5
        self.watcher_job_queue = PriorityQueue()
        self.watcher_db_cur_jobs = {}  # watchid -> job either in queue or processing
        self.watcher_db_processing = {}  # watchid -> time scan started, protected by lock
        self.watcher_db_lock = RLock()
        self.watcher_workers = []
        self.watcher_thread = None

        self.trace_logger = Tracelogger(logger)
        self.crt_sh_proc = CrtProcessor()
        self.tls_handshaker = TlsHandshaker(timeout=5, tls_version='TLS_1_2', attempts=3)
        self.crt_validator = PathValidator()
        self.domain_tools = TlsDomainTools()
        self.tls_scanner = TlsScanner()
        self.test_timeout = 5

        self.cleanup_last_check = 0
        self.cleanup_check_time = 60
        self.cleanup_thread = None
        self.cleanup_thread_lock = RLock()

        self.delta_dns = timedelta(minutes=10)
        self.delta_tls = timedelta(hours=2)
        self.delta_crtsh = timedelta(hours=8)
        self.delta_whois = timedelta(hours=24)

    def check_pid(self, retry=True):
        """
        Check the PID lock ownership
        :param retry:
        :return:
        """
        first_retry = True
        attempt_ctr = 0
        while first_retry or retry:
            try:
                first_retry = False
                attempt_ctr += 1

                self.core.pidlock_create()
                if attempt_ctr > 1:
                    print('\nPID lock acquired')
                return True

            except pid.PidFileAlreadyRunningError as e:
                return True

            except pid.PidFileError as e:
                pidnum = self.core.pidlock_get_pid()
                print('\nError: CLI already running in exclusive mode by PID: %d' % pidnum)

                if self.args.pidlock >= 0 and attempt_ctr > self.args.pidlock:
                    return False

                print('Next check will be performed in few seconds. Waiting...')
                time.sleep(3)
        pass

    def return_code(self, code=0):
        self.last_result = code
        return code

    def init_config(self):
        """
        Initializes configuration
        :return:
        """
        if self.args.ebstall:
            self.config = Config.from_file('/etc/enigma/config.json')
            self.config.mysql_user = 'keychest'
            return

        self.config = Core.read_configuration()
        if self.config is None or not self.config.has_nonempty_config():
            sys.stderr.write('Configuration is empty: %s\nCreating default one... (fill in access credentials)\n'
                             % Core.get_config_file_path())

            Core.write_configuration(Config.default_config())
            return self.return_code(1)

        if self.args.server_debug and self.args.daemon:
            # Server debug causes flask to restart the whole daemon (due to server reloading on code change)
            logger.error('Server debug and daemon are mutually exclusive')
            raise ValueError('Invalid start arguments')

    def init_log(self):
        """
        Initializes logging
        :return:
        """
        util.make_or_verify_dir(self.logdir)

    def init_db(self):
        """
        Initializes the database
        :return:
        """
        self.db = MySQL(config=self.config)
        self.db.init_db()

        # redis init
        self.redis = RedisClient()
        self.redis.init(self.config)
        self.redis_queue = RedisQueue(redis_client=self.redis)

    def init_misc(self):
        """
        Misc components init
        :return: 
        """
        self.crt_validator.init()
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signal, frame):
        """
        Signal handler - terminate gracefully
        :param signal:
        :param frame:
        :return:
        """
        logger.info('CTRL+C pressed')
        self.trigger_stop()

    def trigger_stop(self):
        """
        Sets terminal conditions to true
        :return:
        """
        self.terminate = True
        self.stop_event.set()

    def is_running(self):
        """
        Returns true if termination was not triggered
        :return: 
        """
        return not self.terminate and not self.stop_event.isSet()

    #
    # Interface - Redis interactive jobs
    #

    def process_redis_job(self, job):
        """
        Main redis job processor
        Handles job logic as implemented in Laravel.
        e.g., removes jobs from delay/reserved queues when finished.
        :param job: 
        :return: 
        """
        try:
            # Process job in try-catch so it does not break worker
            logger.info('New job: %s' % json.dumps(job.decoded, indent=4))
            self.scan_mark_failed_if_exceeds(job)

            # Here we will fire off the job and let it process. We will catch any exceptions so
            # they can be reported to the developers logs, etc. Once the job is finished the
            # proper events will be fired to let any listeners know this job has finished.
            self.on_redis_job(job)

            # Once done, delete job from the queue
            if not job.is_deleted_or_released():
                job.delete()

        except Exception as e:
            logger.error('Exception in processing job %s' % (e,))
            self.trace_logger.log(e)

            self.scan_mark_failed_exceeds_attempts(job, 5, e)
            if not job.is_deleted_or_released() and not job.failed:
                job.release()

    def on_redis_job(self, job):
        """
        Main redis job router. Determines which command should be executed. 
        :param job: 
        :return: 
        """
        payload = job.decoded
        if payload is None or 'id' not in payload or 'data' not in payload:
            logger.warning('Invalid job detected: %s' % json.dumps(payload))
            job.delete()
            return

        data = payload['data']
        cmd = data['commandName']
        if cmd == 'App\\Jobs\\ScanHostJob':
            self.on_redis_scan_job(job)
        else:
            logger.warning('Unknown job')
            job.delete()
            return

    def on_redis_scan_job(self, job):
        """
        redis scan job
        :param job: 
        :return: 
        """
        self.augment_redis_scan_job(job)

        job_data = job.decoded['data']['json']
        domain = job_data['scan_host']
        logger.debug(job_data)

        s = None
        self.update_job_state(job_data, 'started')
        try:
            s = self.db.get_session()

            # load job object
            job_db = s.query(ScanJob).filter(ScanJob.uuid == job_data['uuid']).first()

            # TODO: scan CT database
            # ...

            # DNS scan
            self.scan_dns(s, job_data, domain, job_db)
            s.commit()

            self.update_job_state(job_db, 'dns-done', s)

            # crt.sh scan
            self.scan_crt_sh(s, job_data, domain, job_db)
            s.commit()

            self.update_job_state(job_db, 'crtsh-done', s)

            # TODO: search for more subdomains, *.domain, %.domain
            # ...

            # direct host scan
            self.scan_handshake(s, job_data, domain, job_db)
            s.commit()

            self.update_job_state(job_db, 'tls-done', s)

            # whois scan
            self.scan_whois(s, job_data, domain, job_db)
            s.commit()

        finally:
            util.silent_close(s)

        self.update_job_state(job_data, 'finished')
        pass

    def augment_redis_scan_job(self, job=None, data=None):
        """
        Augments job with retry counts, timeouts and so on.
        :param RedisJob job:
        :param data:
        :return:
        """
        if job is not None:
            data = job.decoded['data']['json']

        scan_type = None
        if 'scan_type' in data:
            scan_type = data['scan_type']

        sys_params = collections.OrderedDict()
        sys_params['retry'] = 1
        sys_params['timeout'] = 4

        if scan_type == 'planner':
            sys_params['retry'] = 3
            sys_params['timeout'] = 20

        data['sysparams'] = sys_params
        return data

    def scan_handshake(self, s, job_data, query, job_db, store_job=True):
        """
        Performs direct handshake if applicable
        :param s: 
        :param job_data: 
        :param query: 
        :param job_db:
        :type job_db ScanJob
        :param store_job: stores job to the database in the scanning process.
                          Not storing the job immediately has meaning for diff scanning (watcher).
                          Gathered certificates are stored always.
        :return:
        :rtype Tuple[TlsHandshakeResult, DbHandshakeScanJob]
        """
        domain = job_data['scan_host']
        domain_sni = util.defvalkey(job_data, 'scan_sni', domain)
        dns_ok = util.defvalkey(job_data, 'dns_ok', True, take_none=False)
        sys_params = job_data['sysparams']
        if not TlsDomainTools.can_connect(domain):
            logger.debug('Domain %s not elligible to handshake' % domain)
            return

        port = int(util.defvalkey(job_data, 'scan_port', 443, take_none=False))
        scheme = util.defvalkey(job_data, 'scan_scheme', None, take_none=False)

        # Simple TLS handshake to the given host.
        # Analyze results, store scan record.
        try:
            resp = None
            try:
                resp = self.tls_handshaker.try_handshake(domain, port, scheme=scheme,
                                                         attempts=sys_params['retry'],
                                                         timeout=sys_params['timeout'],
                                                         domain=domain_sni)

            except TlsTimeout as te:
                logger.debug('Scan timeout: %s' % te)
                resp = te.scan_result
            except TlsException as te:
                logger.debug('Scan fail: %s' % te)
                resp = te.scan_result

            logger.debug(resp)
            time_elapsed = None
            if resp.time_start is not None and resp.time_finished is not None:
                time_elapsed = (resp.time_finished - resp.time_start)*1000
            if time_elapsed is None and resp.time_start is not None and resp.time_failed is not None:
                time_elapsed = (resp.time_failed - resp.time_start)*1000

            # scan record
            scan_db = DbHandshakeScanJob()
            scan_db.created_at = salch.func.now()
            scan_db.job_id = job_db.id if job_db is not None else None
            scan_db.ip_scanned = resp.ip if resp.ip is not None else '-'  # placeholder IP, group by fix
            scan_db.tls_ver = resp.tls_version
            scan_db.status = len(resp.certificates) > 0
            scan_db.err_code = resp.handshake_failure
            scan_db.time_elapsed = time_elapsed
            scan_db.results = len(resp.certificates)
            scan_db.new_results = 0
            if store_job:
                s.add(scan_db)
                s.flush()

            # Certificates processing + cert path validation
            self.process_handshake_certs(s, resp, scan_db, do_job_subres=store_job)

            # Try direct connect with requests, follow urls
            if dns_ok:
                self.connect_analysis(s, sys_params, resp, scan_db, domain_sni, port, scheme)
            else:
                logger.debug('Connect analysis skipped for %s' % domain_sni)

            return resp, scan_db

        except Exception as e:
            logger.debug('Exception when scanning: %s' % e)
            self.trace_logger.log(e)
        return None, None

    def scan_crt_sh(self, s, job_data, query, job_db, store_to_db=True):
        """
        Performs one simple CRT SH scan with the given query
        stores the resuls.
        
        :param s: 
        :param job_data: 
        :param domain: 
        :param job_db:
        :type job_db ScanJob
        :param store_to_db if true results are stored to the database, otherwise just returned.
               Gathered certificates are stored always.

        :return:
        :rtype Tuple[DbCrtShQuery, List[DbCrtShQueryResult]]
        """
        crt_sh = self.crt_sh_proc.query(query)
        logger.debug(crt_sh)
        if crt_sh is None:
            return

        # existing certificates - have pem
        all_crt_ids = set([int(x.id) for x in crt_sh.results if x is not None and x.id is not None])
        existing_ids = self.cert_load_existing(s, list(all_crt_ids))
        existing_ids_set = set(existing_ids.keys())
        new_ids = all_crt_ids - existing_ids_set

        # certificate ids
        certs_ids = list(existing_ids.values())

        # scan record
        crtsh_query_db = DbCrtShQuery()
        crtsh_query_db.created_at = salch.func.now()
        crtsh_query_db.job_id = job_db.id if job_db is not None else None
        crtsh_query_db.status = crt_sh.success
        crtsh_query_db.results = len(all_crt_ids)
        crtsh_query_db.new_results = len(new_ids)
        if store_to_db:
            s.add(crtsh_query_db)
            s.flush()
            if job_db is not None:
                job_db.crtsh_check_id = crtsh_query_db.id
                job_db = s.merge(job_db)

        # existing records
        sub_res_list = []
        for crt_sh_id in existing_ids:
            crtsh_res_db = DbCrtShQueryResult()
            crtsh_res_db.query_id = crtsh_query_db.id
            crtsh_res_db.job_id = crtsh_query_db.job_id
            crtsh_res_db.crt_id = existing_ids[crt_sh_id]
            crtsh_res_db.crt_sh_id = crt_sh_id
            crtsh_res_db.was_new = 0
            sub_res_list.append(crtsh_res_db)
            if store_to_db:
                s.add(crtsh_res_db)

        # load pem for new certificates
        for new_crt_id in sorted(list(new_ids), reverse=True)[:100]:
            db_cert, subres = \
                self.fetch_new_certs(s, job_data, new_crt_id,
                                     [x for x in crt_sh.results if int(x.id) == new_crt_id][0],
                                     crtsh_query_db, store_res=store_to_db)
            if db_cert is not None:
                certs_ids.append(db_cert.id)
            if subres is not None:
                sub_res_list.append(subres)

        for cert in crt_sh.results:
            self.analyze_cert(s, job_data, cert)

        crtsh_query_db.certs_ids = json.dumps(sorted(certs_ids))
        return crtsh_query_db, sub_res_list

    def scan_whois(self, s, job_data, query, job_db, store_to_db=True):
        """
        Performs whois scan if applicable
        :param s:
        :param job_data:
        :param query:
        :param job_db:
        :type job_db ScanJob
        :param store_to_db: stores job to the database in the scanning process.
                          Not storing the job immediately has meaning for diff scanning (watcher).
        :return:
        :rtype DbWhoisCheck
        """
        domain = job_data['scan_host']
        sys_params = job_data['sysparams']
        if not TlsDomainTools.can_whois(domain):
            logger.debug('Domain %s not elligible to whois scan' % domain)
            return

        try:
            top_domain = TlsDomainTools.get_top_domain(domain)
            top_domain_db, domain_new = self.load_top_domain(s, top_domain=top_domain)

            last_scan = self.load_last_whois_scan(s, top_domain_db) if not domain_new else None
            if last_scan is not None and last_scan.last_scan_at > self._diff_time(self.delta_whois):
                if job_db is not None:
                    job_db.whois_check_id = last_scan.id
                    job_db = s.merge(job_db)
                return last_scan

            scan_db = DbWhoisCheck()
            scan_db.domain = top_domain_db
            scan_db.last_scan_at = datetime.now()
            scan_db.created_at = salch.func.now()
            scan_db.updated_at = salch.func.now()
            resp = None
            try:
                resp = self.try_whois(top_domain, attempts=sys_params['retry'])
                if resp is None:  # not found
                    scan_db.result = 2
                else:
                    scan_db.registrant_cc = util.first(resp.country)
                    scan_db.registrar = util.first(resp.registrar)
                    scan_db.expires_at = util.first(resp.expiration_date)
                    scan_db.registered_at = util.first(resp.creation_date)
                    scan_db.rec_updated_at = util.first(resp.updated_date)
                    scan_db.dnssec = not util.is_empty(resp.dnssec) and resp.dnssec != 'unsigned'
                    scan_db.dns = json.dumps(util.lower(util.strip(
                        sorted(util.try_list(resp.name_servers)))))
                    scan_db.emails = json.dumps(util.lower(util.strip(
                        sorted(util.try_list(resp.emails)))))
                    scan_db.result = 1

            except Exception as e:
                scan_db.result = 0
                logger.debug('Whois scan fail: %s' % e)
                self.trace_logger.log(e, custom_msg='Whois exception')

            if store_to_db:
                s.add(scan_db)
                s.flush()
                if job_db is not None:
                    job_db.whois_check_id = scan_db.id
                    job_db = s.merge(job_db)

            return scan_db

        except Exception as e:
            logger.debug('Exception in whois scan: %s' % e)
            self.trace_logger.log(e)

    def scan_dns(self, s, job_data, query, job_db, store_to_db=True):
        """
        Performs DNS scan
        :param s:
        :param job_data:
        :param query:
        :param job_db:
        :type job_db Optional[ScanJob]
        :param store_job: stores job to the database in the scanning process.
                          Not storing the job immediately has meaning for diff scanning (watcher).
        :return:
        :rtype DbDnsResolve
        """
        domain = job_data['scan_host']
        watch_id = util.defvalkey(job_data, 'watch_id')
        if not TlsDomainTools.can_whois(domain):
            logger.debug('Domain %s not elligible to DNS scan' % domain)
            return

        scan_db = DbDnsResolve()
        scan_db.watch_id = watch_id
        scan_db.job_id = job_db.id if job_db is not None else None
        scan_db.last_scan_at = datetime.now()
        scan_db.created_at = salch.func.now()
        scan_db.updated_at = salch.func.now()

        try:
            results = socket.getaddrinfo(domain, 443,
                                         socket.AF_INET,
                                         socket.SOCK_STREAM,
                                         socket.IPPROTO_TCP)

            res = []
            for cur in results:
                res.append((cur[0], cur[4][0]))

            res.sort()
            scan_db.dns_res = res
            scan_db.dns_status = 0
            scan_db.status = 0
            scan_db.dns = json.dumps(res)

            if store_to_db:
                s.add(scan_db)
                s.flush()
                if job_db is not None:
                    job_db.dns_check_id = scan_db.id
                    job_db = s.merge(job_db)

            return scan_db

        except socket.gaierror as gai:
            logger.debug('GAI error: %s: %s' % (domain, gai))
            scan_db.status = 1
            scan_db.dns_status = 1
            return scan_db

        except Exception as e:
            logger.debug('Exception in DNS scan: %s : %s' % (domain, e))
            scan_db.status = 2
            scan_db.dns_status = 2
            self.trace_logger.log(e)

    #
    # Periodic scanner
    #

    def load_active_watch_targets(self, s, last_scan_margin=300):
        """
        Loads active jobs to scan, from the oldest.
        After loading the result is a tuple (DbWatchTarget, min_periodicity).

        select wt.*, min(uw.scan_periodicity) from user_watch_target uw
            inner join watch_target wt on wt.id = uw.watch_id
            where uw.deleted_at is null
            group by wt.id, uw.scan_type
            order by last_scan_state desc;
        :param s : SaQuery query
        :type s: SaQuery
        :param last_scan_margin: margin for filtering out records that were recently processed.
        :return:
        """
        q = s.query(
                    DbWatchTarget,
                    salch.func.min(DbWatchAssoc.scan_periodicity).label('min_periodicity')
        )\
            .select_from(DbWatchAssoc)\
            .join(DbWatchTarget, DbWatchAssoc.watch_id == DbWatchTarget.id)\
            .filter(DbWatchAssoc.deleted_at == None)

        if last_scan_margin:
            cur_margin = datetime.now() - timedelta(seconds=last_scan_margin)
            q = q.filter(salch.or_(
                DbWatchTarget.last_scan_at < cur_margin,
                DbWatchTarget.last_scan_at == None
            ))

        return q.group_by(DbWatchTarget.id, DbWatchAssoc.scan_type)\
                .order_by(DbWatchTarget.last_scan_at)  # select the oldest scanned first

    def _min_scan_margin(self):
        """
        Computes minimal scan margin from the scan timeouts
        :return:
        """
        return min(self.delta_dns, self.delta_tls, self.delta_crtsh, self.delta_whois).seconds

    def periodic_feeder_main(self):
        """
        Main thread feeding periodic scan job queue from database - according to the records.
        :return:
        """
        while self.is_running():
            ctime = time.time()

            # trigger if last scan was too old / queue is empty / on event from the interface
            scan_now = False
            if self.watch_last_db_scan + self.watch_db_scan_period <= ctime:
                scan_now = True

            if not scan_now and self.watch_last_db_scan + 2 <= ctime \
                    and self.watcher_job_queue.qsize() <= 100:
                scan_now = True

            if not scan_now:
                time.sleep(0.5)
                continue

            # get the new session
            try:
                self.periodic_feeder()

            except Exception as e:
                logger.error('Exception in processing job %s' % (e, ))
                self.trace_logger.log(e)

            finally:
                self.watch_last_db_scan = ctime

        logger.info('Periodic feeder terminated')

    def periodic_feeder(self):
        """
        Feeder loop body
        :return:
        """
        if self.watcher_job_queue.full():
            return

        s = self.db.get_session()
        min_scan_margin = self._min_scan_margin()
        try:
            query = self.load_active_watch_targets(s, last_scan_margin=min_scan_margin)
            iterator = query.yield_per(100)
            for x in iterator:
                watch_target, min_periodicity = x

                if self.watcher_job_queue.full():
                    return

                with self.watcher_db_lock:
                    # Ignore jobs currently in the progress.
                    if watch_target.id in self.watcher_db_cur_jobs:
                        continue

                    # TODO: analyze if this job should be processed or results are recent, no refresh is needed
                    job = PeriodicJob(target=watch_target, periodicity=min_periodicity)
                    self.watcher_db_cur_jobs[job.key()] = job
                    self.watcher_job_queue.put(job)
                    logger.debug('Job generated: %s, qsize: %s' % (str(job), self.watcher_job_queue.qsize()))

        finally:
            util.silent_close(s)

    def periodic_worker_main(self, idx):
        """
        Main periodic job worker
        :param idx:
        :return:
        """
        self.local_data.idx = idx
        logger.info('Periodic Scanner Worker %02d started' % idx)

        while self.is_running():
            job = None
            try:
                job = self.watcher_job_queue.get(True, timeout=1.0)
            except QEmpty:
                time.sleep(0.1)
                continue

            try:
                # Process job in try-catch so it does not break worker
                logger.debug('[%02d] Processing job' % (idx,))
                self.periodic_process_job(job)

            except Exception as e:
                logger.error('Exception in processing watch job %s: %s' % (e, job))
                self.trace_logger.log(e)

            finally:
                self.watcher_job_queue.task_done()

        logger.info('Periodic Worker %02d terminated' % idx)

    def periodic_process_job(self, job):
        """
        Processes periodic job - wrapper
        :param job:
        :type job: PeriodicJob
        :return:
        """
        try:
            with self.watcher_db_lock:
                self.watcher_db_processing[job.key()] = job

            self.periodic_process_job_body(job)

        except Exception as e:
            logger.error('Exception in processing watcher job %s' % (e,))
            self.trace_logger.log(e)

        finally:
            remove_job = True

            # if job is success update db last scan value
            if job.success_scan:
                self.periodic_update_last_scan(job)

            # if retry under threshold, add again to the queue
            elif job.attempts <= 3:
                self.watcher_job_queue.put(job)
                remove_job = False

            # The job has expired.
            # TODO: make sure job does not return quickly by DB load - add backoff / num of fails / last fail
            # remove from processing caches so it can be picked up again later.
            # i.e. remove lock on this item
            if remove_job:
                with self.watcher_db_lock:
                    del self.watcher_db_cur_jobs[job.key()]
                    del self.watcher_db_processing[job.key()]

    def periodic_update_last_scan(self, job):
        """
        Updates last scan time for the job
        :param job:
        :type job: PeriodicJob
        :return:
        """
        s = self.db.get_session()
        try:
            stmt = DbWatchTarget.__table__.update()\
                .where(DbWatchTarget.id == job.target.id)\
                .values(last_scan_at=salch.func.now())
            s.execute(stmt)
            s.commit()

        finally:
            util.silent_close(s)

    def periodic_process_job_body(self, job):
        """
        Watcher job processing - the body
        :param job:
        :type job: PeriodicJob
        :return:
        """
        logger.debug('Processing watcher job: %s' % job)
        s = self.db.get_session()
        try:
            self.periodic_scan_dns(s, job)
            self.periodic_scan_tls(s, job)
            self.periodic_scan_crtsh(s, job)
            self.periodic_scan_whois(s, job)

            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.scan_dns.is_failed() \
                    or job.scan_tls.is_failed() \
                    or job.scan_whois.is_failed() \
                    or job.scan_crtsh.is_failed():
                logger.info('Job failed, dns: %s, tls: %s, whois: %s, crtsh: %s'
                            % (job.scan_dns.is_failed(), job.scan_tls.is_failed(),
                               job.scan_whois.is_failed(), job.scan_crtsh.is_failed()))

                job.attempts += 1
                job.success_scan = False
            else:
                job.success_scan = True

        except Exception as e:
            logger.debug('Exception when processing the watcher job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_close(s)

    def periodic_scan_dns(self, s, job):
        """
        Periodic DNS scan - determines if the check is required, invokes the check
        :param job:
        :type job: PeriodicJob
        :return:
        """
        job_scan = job.scan_dns  # type: ScanResults
        last_scan = self.load_last_dns_scan(s, job.watch_id())
        if last_scan is not None and last_scan.last_scan_at > self._diff_time(self.delta_dns):
            job_scan.skip(last_scan)
            self.wp_process_dns(s, job, job_scan.aux)
            return  # scan is relevant enough

        try:
            self.wp_scan_dns(s, job, last_scan)

        except Exception as e:
            job_scan.fail()

            logger.error('DNS scan exception: %s' % e)
            self.trace_logger.log(e, custom_msg='DNS scan')

    def periodic_scan_tls(self, s, job):
        """
        Periodic TLS scan - determines if the check is required, invokes the check
        :param job:
        :type job: PeriodicJob
        :return:
        """
        job_scan = job.scan_tls  # type: ScanResults

        prev_scans = self.load_last_tls_scan(s, job.watch_id())
        prev_scans_map = {x.ip_scanned: x for x in prev_scans}
        primary_scan = util.defvalkey(prev_scans_map, job.primary_ip) if job.primary_ip is not None else None

        if primary_scan is not None and primary_scan.last_scan_at > self._diff_time(self.delta_tls):
            job_scan.skip(prev_scans_map)
            return  # scan is relevant enough

        try:
            self.wp_scan_tls(s, job, prev_scans_map)

        except Exception as e:
            job_scan.fail()

            logger.error('TLS scan exception: %s' % e)
            self.trace_logger.log(e, custom_msg='TLS scan')

    def periodic_scan_crtsh(self, s, job):
        """
        Periodic CRTsh scan - determines if the check is required, invokes the check
        :param job:
        :type job: PeriodicJob
        :return:
        """
        job_scan = job.scan_crtsh  # type: ScanResults

        last_scan = self.load_last_crtsh_scan(s, job.watch_id())
        if last_scan is not None and last_scan.last_scan_at > self._diff_time(self.delta_crtsh):
            job_scan.skip(last_scan)
            return  # scan is relevant enough

        try:
            self.wp_scan_crtsh(s, job, last_scan)

        except Exception as e:
            job_scan.fail()

            logger.error('CRT sh exception: %s' % e)
            self.trace_logger.log(e, custom_msg='CRT sh')

    def periodic_scan_whois(self, s, job):
        """
        Periodic Whois scan - determines if the check is required, invokes the check
        :param job:
        :type job: PeriodicJob
        :return:
        """
        url = self.urlize(job)
        job_scan = job.scan_whois  # type: ScanResults

        if not TlsDomainTools.can_whois(url.host):
            job_scan.skip()
            return  # has IP address only, no whois check

        top_domain = TlsDomainTools.get_top_domain(url.host)
        last_scan = self.load_last_whois_scan(s, top_domain)
        if last_scan is not None and last_scan.last_scan_at > self._diff_time(self.delta_whois):
            job_scan.skip(last_scan)
            return  # scan is relevant enough

        # initiate new whois check
        try:
            self.wp_scan_whois(s=s, job=job, url=url, top_domain=top_domain, last_scan=last_scan)

        except Exception as e:
            job_scan.fail()

            logger.error('Whois exception: %s' % e)
            self.trace_logger.log(e, custom_msg='Whois')

    #
    # Scan bodies
    #

    def _create_job_spec(self, job):
        """
        Builds job defs for scan - like job spec coming from frontend
        :param job:
        :type job: PeriodicJob
        :return:
        """
        data = collections.OrderedDict()
        data['uuid'] = None
        data['state'] = 'init'
        data['scan_type'] = 'planner'
        data['user_id'] = job.target.user_id

        url = self.urlize(job)
        data['scan_scheme'] = url.scheme
        data['scan_host'] = url.host
        data['scan_port'] = url.port
        data['scan_url'] = url

        data = self.augment_redis_scan_job(data=data)
        return data

    def wp_scan_dns(self, s, job, last_scan):
        """
        Watcher DNS scan - body
        :param job:
        :type job: PeriodicJob
        :param last_scan:
        :type last_scan: DbDnsResolve
        :return:
        """
        job_scan = job.scan_dns  # type: ScanResults
        job_spec = self._create_job_spec(job)
        url = self.urlize(job)

        cur_scan = self.scan_dns(s=s, job_data=job_spec, query=url.host, job_db=None, store_to_db=False)
        if cur_scan is None:
            job_scan.fail()
            return

        is_same_as_before = self.diff_scan_dns(cur_scan, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1
            job_scan.aux = last_scan

        else:
            cur_scan.watch_id = job.target.id
            cur_scan.num_scans = 1
            cur_scan.updated_ad = salch.func.now()
            cur_scan.last_scan_at = salch.func.now()
            s.add(cur_scan)

            job_scan.aux = cur_scan

        s.commit()

        # Store scan history
        hist = DbScanHistory()
        hist.watch_id = job.target.id
        hist.scan_type = 4  # dns scan
        hist.scan_code = 0
        hist.created_at = salch.func.now()
        s.add(hist)
        s.commit()

        # TODO: store gap if there is one
        # - compare last scan with the SLA periodicity. multiple IP addressess make it complicated...

        # finished with success
        self.wp_process_dns(s, job, job_scan.aux)
        job_scan.ok()

    def wp_process_dns(self, s, job, last_scan):
        """
        Processes DNS scan, sets primary IP address
        :param s:
        :param job:
        :type job: ScanJob
        :param last_scan:
        :type last_scan: DbDnsResolve
        :return:
        """
        if last_scan and last_scan.dns_res and len(last_scan.dns_res) > 0:
            domains = sorted(last_scan.dns_res)
            job.primary_ip = domains[0][1]
        else:
            job.primary_ip = None

    def wp_scan_tls(self, s, job, scan_list):
        """
        Watcher TLS scan - body
        :param job:
        :type job: PeriodicJob
        :param last_scan:
        :type last_scan: DbHandshakeScanJob
        :return:
        """
        job_scan = job.scan_tls  # type: ScanResults
        job_spec = self._create_job_spec(job)
        url = self.urlize(job)

        if TlsDomainTools.can_whois(url.host):
            job_spec['scan_sni'] = url.host

        # For now - scan only first IP address in the lexi ordering
        # TODO: scan all IPs, perform extended handshake test on all resolved IPs
        if job.primary_ip:
            job_spec['scan_host'] = job.primary_ip
            job_spec['dns_ok'] = True
        else:
            job_scan.skip(scan_list)  # skip TLS handshake check totally if DNS is not valid
            return

        handshake_res, db_scan = self.scan_handshake(s, job_spec, url.host, None, store_job=False)
        if handshake_res is None:
            return

        last_scan = util.defvalkey(scan_list, db_scan.ip_scanned, None)

        # Compare with last result, store if new one or update the old one
        # LATER: define fields on the model which difference is interesting to store
        is_same_as_before = self.diff_scan_tls(db_scan, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1
            last_scan = s.merge(last_scan)
        else:
            db_scan.watch_id = job.target.id
            db_scan.num_scans = 1
            db_scan.last_scan_at = salch.func.now()
            db_scan.updated_ad = salch.func.now()
            s.add(db_scan)
            logger.info('TLS scan is different, lastscan: %s for %s' % (last_scan, db_scan.ip_scanned))

        s.commit()

        # Store scan history
        hist = DbScanHistory()
        hist.watch_id = job.target.id
        hist.scan_type = 1
        hist.scan_code = 0
        hist.created_at = salch.func.now()
        s.add(hist)
        s.commit()

        # TODO: store gap if there is one
        # - compare last scan with the SLA periodicity. multiple IP addressess make it complicated...

        # finished with success
        job_scan.ok()

    def wp_scan_crtsh(self, s, job, last_scan):
        """
        Watcher crt.sh scan - body
        :param job:
        :type job: PeriodicJob
        :param last_scan:
        :type last_scan: DbCrtShQuery
        :return:
        """
        job_scan = job.scan_crtsh  # type: ScanResults
        job_spec = self._create_job_spec(job)
        url = self.urlize(job)

        crtsh_query_db, sub_res_list = self.scan_crt_sh(
            s=s, job_data=job_spec, query=url.host, job_db=None, store_to_db=False)

        is_same_as_before = self.diff_scan_crtsh(crtsh_query_db, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1
            last_scan = s.merge(last_scan)
        else:
            crtsh_query_db.watch_id = job.target.id
            crtsh_query_db.num_scans = 1
            crtsh_query_db.updated_ad = salch.func.now()
            crtsh_query_db.last_scan_at = salch.func.now()
            s.add(crtsh_query_db)

        s.commit()

        # Store scan history
        hist = DbScanHistory()
        hist.watch_id = job.target.id
        hist.scan_type = 2  # crtsh scan
        hist.scan_code = 0
        hist.created_at = salch.func.now()
        s.add(hist)
        s.commit()

        # TODO: store gap if there is one
        # - compare last scan with the SLA periodicity. multiple IP addressess make it complicated...

        # finished with success
        job_scan.ok()

    def wp_scan_whois(self, s, job, url, top_domain, last_scan):
        """
        Watcher whois scan - body
        :param job:
        :type job: PeriodicJob
        :param url:
        :param top_domain:
        :param last_scan:
        :type last_scan: DbWhoisCheck
        :return:
        """
        job_scan = job.scan_whois  # type: ScanResults
        job_spec = self._create_job_spec(job)
        url = self.urlize(job)

        scan_db = self.scan_whois(s=s, job_data=job_spec, query=top_domain, job_db=None, store_to_db=False)

        # Compare with last result, store if new one or update the old one
        # LATER: define fields on the model which difference is interesting to store
        is_same_as_before = self.diff_scan_whois(scan_db, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1
            last_scan = s.merge(last_scan)
        else:
            scan_db.watch_id = job.target.id
            scan_db.num_scans = 1
            scan_db.updated_ad = salch.func.now()
            scan_db.last_scan_at = salch.func.now()
            s.add(scan_db)

        s.commit()

        # Store scan history
        hist = DbScanHistory()
        hist.watch_id = job.target.id
        hist.scan_type = 3  # whois
        hist.scan_code = 0
        hist.created_at = salch.func.now()
        s.add(hist)
        s.commit()

        # TODO: store gap if there is one
        # - compare last scan with the SLA periodicity. multiple IP addressess make it complicated...

        # TODO: construct db result, merge results to the database.
        job_scan.ok()

    #
    # Scan Results
    #

    def _res_compare_cols_tls(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
        TODO: transform follow urls - strip query path
        :return:
        """
        m = DbHandshakeScanJob  # model, alias
        cols = [
            m.ip_scanned, m.tls_ver, m.status, m.err_code, m.results, m.certs_ids, m.cert_id_leaf,
            m.valid_path, m.valid_hostname, m.err_validity, m.err_many_leafs,
            m.req_https_result, m.follow_http_result, m.follow_https_result,
            ColTransformWrapper(m.follow_http_url, TlsDomainTools.strip_query),
            ColTransformWrapper(m.follow_https_url, TlsDomainTools.strip_query),
            m.hsts_present, m.hsts_max_age, m.hsts_include_subdomains, m.hsts_preload,
            m.pinning_present, m.pinning_report_only, m.pinning_pins]
        return cols

    def _scan_tuple_tls(self, x, is_loaded=False):
        """
        X to the tuple for change comparison.
        TODO: transform function for certain columns - e.g., follow url, strip query path -
            contains random sessions sometimes
        :param x:
        :type x: DbHandshakeScanJob
        :return:
        """
        if x is None:
            return None

        cols = self._res_compare_cols_tls()
        return DbHelper.project_model(x, cols, default_vals=True)

    def diff_scan_tls(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbHandshakeScanJob
        :param last_scan:
        :type last_scan: DbHandshakeScanJob
        :return:
        """
        # Uses tuple comparison for now. Later it could do comparison by defining
        # columns sensitive for a change dbutil.DbHandshakeScanJob.__table__.columns and getattr(model, col).
        t1 = self._scan_tuple_tls(cur_scan)
        t2 = self._scan_tuple_tls(last_scan)
        for i in range(len(t1)):
            if t1 and t2 and t1[i] != t2[i]:
                logger.debug('Diff: %s, %s != %s col %s' % (i, t1[i], t2[i], self._res_compare_cols_tls()[i]))
        return t1 == t2

    def _res_compare_cols_crtsh(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
        :return:
        """
        m = DbCrtShQuery
        return [m.status, m.results, m.certs_ids]

    def _scan_tuple_crtsh(self, x):
        """
        X to the tuple for change comparison.
        :param x:
        :type x: DbCrtShQuery
        :return:
        """
        if x is None:
            return None
        cols = self._res_compare_cols_crtsh()
        return DbHelper.project_model(x, cols, default_vals=True)

    def diff_scan_crtsh(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbCrtShQuery
        :param last_scan:
        :type last_scan: DbCrtShQuery
        :return:
        """
        return self._scan_tuple_crtsh(cur_scan) == self._scan_tuple_crtsh(last_scan)

    def _res_compare_cols_whois(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
        :return:
        """
        m = DbWhoisCheck
        return [m.status, m.registrant_cc, m.registrar, m.registered_at, m.expires_at,
                m.rec_updated_at, m.dns, m.aux]

    def _scan_tuple_whois(self, x):
        """
        X to the tuple for change comparison.
        :param x:
        :type x: DbWhoisCheck
        :return:
        """
        if x is None:
            return None
        cols = self._res_compare_cols_whois()
        return DbHelper.project_model(x, cols, default_vals=True)

    def diff_scan_whois(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbWhoisCheck
        :param last_scan:
        :type last_scan: DbWhoisCheck
        :return:
        """
        return self._scan_tuple_whois(cur_scan) == self._scan_tuple_whois(last_scan)

    def _res_compare_cols_dns(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
        :return:
        """
        m = DbDnsResolve
        return [m.status, m.dns]

    def _scan_tuple_dns(self, x):
        """
        X to the tuple for change comparison.
        :param x:
        :type x: DbDnsResolve
        :return:
        """
        if x is None:
            return None
        cols = self._res_compare_cols_dns()
        return DbHelper.project_model(x, cols, default_vals=True)

    def diff_scan_dns(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbDnsResolve
        :param last_scan:
        :type last_scan: DbDnsResolve
        :return:
        """
        return self._scan_tuple_dns(cur_scan) == self._scan_tuple_dns(last_scan)

    #
    # Scan helpers
    #

    def load_last_tls_scan(self, s, watch_id=None, ip=None):
        """
        Loads the most recent tls handshake scan result for given watch
        target id and optionally the IP address.
        TODO: all IP addresses
        :param s:
        :param watch_id:
        :param ip:
        :return:
        :rtype DbHandshakeScanJob
        """
        if ip is not None:
            q = s.query(DbHandshakeScanJob).filter(DbHandshakeScanJob.watch_id == watch_id)
            q = q.filter(DbHandshakeScanJob.ip_scanned == ip)
            return q.order_by(DbHandshakeScanJob.last_scan_at.desc()).limit(1).first()

        dialect = util.lower(str(s.bind.dialect.name))
        if dialect.startswith('mysql'):

            group_up = dbutil.assign(
                literal_column('group'),
                DbHandshakeScanJob.ip_scanned).label('grpx')

            rank = case([(
                literal_column('@group') != DbHandshakeScanJob.ip_scanned,
                literal_column('@rownum := 1')
            )], else_=literal_column('@rownum := @rownum + 1')
            ).label('rank')

            subq = s.query(DbHandshakeScanJob)\
                .add_column(rank)\
                .add_column(group_up)

            subr = s.query(
                dbutil.assign(literal_column('rownum'),
                              literal_column('0', type_=salch.types.Numeric())).label('rank'),
                dbutil.assign(literal_column('group'),
                              literal_column('-1', type_=salch.types.Numeric())).label('grpx'),
            ).subquery('r')

            subq = subq.join(subr, salch.sql.expression.literal(True))
            subq = subq.filter(DbHandshakeScanJob.watch_id == watch_id)
            subq = subq.filter(DbHandshakeScanJob.ip_scanned != None)
            subq = subq.order_by(DbHandshakeScanJob.ip_scanned, DbHandshakeScanJob.last_scan_at.desc())
            subq = subq.subquery('x')

            qq = s.query(DbHandshakeScanJob)\
                .join(subq, subq.c.id == DbHandshakeScanJob.id)\
                .filter(subq.c.rank <= 1)
            res = qq.all()
            return res

        else:
            row_number_column = salch.func \
                .row_number() \
                .over(partition_by=DbHandshakeScanJob.ip_scanned,
                      order_by=DbHandshakeScanJob.last_scan_at.desc()) \
                .label('row_number')

            query = s.query(DbHandshakeScanJob)
            query = query.add_column(row_number_column)
            query = query.filter(DbHandshakeScanJob.watch_id == watch_id)
            query = query.filter(DbHandshakeScanJob.ip_scanned != None)
            query = query.from_self().filter(row_number_column == 1)
            return query.all()

    def load_last_crtsh_scan(self, s, watch_id=None):
        """
        Loads the latest crtsh scan for the given watch target id
        :param s:
        :param watch_id:
        :return:
        :rtype DbCrtShQuery
        """
        q = s.query(DbCrtShQuery).filter(DbCrtShQuery.watch_id == watch_id)
        return q.order_by(DbCrtShQuery.last_scan_at.desc()).limit(1).first()

    def load_last_whois_scan(self, s, top_domain):
        """
        Loads the latest Whois scan for the top domain
        :param s:
        :param top_domain:
        :return:
        :rtype DbWhoisCheck
        """
        if not isinstance(top_domain, DbBaseDomain):
            top_domain, is_new = self.load_top_domain(s, top_domain)
            if is_new:
                return None  # non-existing top domain, no result then

        q = s.query(DbWhoisCheck).filter(DbWhoisCheck.domain == top_domain)
        return q.order_by(DbWhoisCheck.last_scan_at.desc()).limit(1).first()

    def load_last_dns_scan(self, s, watch_id=None):
        """
        Loads the latest DNS scan
        :param s:
        :param watch_id:
        :return:
        :rtype DbDnsResolve
        """
        if watch_id is None:
            return None
        q = s.query(DbDnsResolve).filter(DbDnsResolve.watch_id == watch_id)
        return q.order_by(DbDnsResolve.last_scan_at.desc()).limit(1).first()

    #
    # Helpers
    #

    def _diff_time(self, delta=None, days=None, seconds=None, hours=None):
        """
        Returns now - diff time
        :param delta:
        :param seconds:
        :param hours:
        :return:
        """
        now = datetime.now()
        if delta is not None:
            return now - delta
        return now - timedelta(days=days, hours=hours, seconds=seconds)

    def urlize(self, obj):
        """
        Extracts URL object
        :param obj:
        :return:
        """
        if isinstance(obj, PeriodicJob):
            return obj.url()
        elif isinstance(obj, DbWatchTarget):
            return TargetUrl(scheme=obj.scan_scheme, host=obj.scan_host, port=obj.scan_port)
        elif isinstance(obj, ScanJob):
            return TargetUrl(scheme=obj.scan_scheme, host=obj.scan_host, port=obj.scan_port)
        else:
            return TlsDomainTools.urlize(obj)

    def parse_certificate(self, cert_db, pem=None, der=None):
        """
        Parses the certificate, returns the parsed cert
        :param cert_db: 
        :param pem: 
        :param der: 
        :return: (cryptography cert, list of alt names)
        """
        cert = None
        if pem is not None:
            cert = util.load_x509(str(cert_db.pem))
        elif der is not None:
            cert = util.load_x509_der(der)
        else:
            raise ValueError('No certificate provided')

        alt_names = [util.utf8ize(x) for x in util.try_get_san(cert)]

        cert_db.cname = util.utf8ize(util.try_get_cname(cert))
        cert_db.fprint_sha1 = util.lower(util.try_get_fprint_sha1(cert))
        cert_db.fprint_sha256 = util.lower(util.try_get_fprint_sha256(cert))
        cert_db.valid_from = util.dt_norm(cert.not_valid_before)
        cert_db.valid_to = util.dt_norm(cert.not_valid_after)
        cert_db.subject = util.utf8ize(util.get_dn_string(cert.subject))
        cert_db.issuer = util.utf8ize(util.get_dn_string(cert.issuer))
        cert_db.is_ca = util.try_is_ca(cert)
        cert_db.is_precert = util.try_is_precert(cert)
        cert_db.is_precert_ca = util.try_is_precert_ca(cert)
        cert_db.is_self_signed = util.try_is_self_signed(cert)
        cert_db.is_le = 'Let\'s Encrypt' in cert_db.issuer

        alt_name_test = list(alt_names)
        if not util.is_empty(cert_db.cname):
            alt_name_test.append(cert_db.cname)

        cert_db.is_cloudflare = len([x for x in alt_name_test if '.cloudflaressl.com' in x]) > 0
        cert_db.alt_names = json.dumps(alt_names)

        return cert, alt_names

    def process_handshake_certs(self, s, resp, scan_db, do_job_subres=True):
        """
        Processes certificates from the handshake
        :return: 
        """
        if util.is_empty(resp.certificates):
            return

        # pre-parsing, get fprints for later load
        local_db = []
        fprints_handshake = set()
        for der in resp.certificates:
            try:
                cert_db = Certificate()
                cert, alt_names = self.parse_certificate(cert_db, der=der)
                local_db.append((cert_db, cert, alt_names, der))
                fprints_handshake.add(cert_db.fprint_sha1)

            except Exception as e:
                logger.error('Exception when downloading a certificate %s' % (e, ))
                self.trace_logger.log(e)

        # load existing certificates
        cert_existing = self.cert_load_fprints(s, list(fprints_handshake))
        leaf_cert_id = None
        all_cert_ids = set()
        num_new_results = 0
        prev_id = None

        # store non-existing certificates from the TLS scan to the database
        for endb in reversed(local_db):
            cert_db, cert, alt_names, der = endb
            fprint = cert_db.fprint_sha1

            try:
                cert_db.created_at = salch.func.now()
                cert_db.pem = '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----' % (base64.b64encode(der),)
                cert_db.source = 'handshake'
                if cert_db.parent_id is None:
                    cert_db.parent_id = prev_id

                # new certificate - add
                # lockfree - add, if exception on add, try fetch, then again add,
                if fprint not in cert_existing:
                    cert_db, is_new_cert = self._add_cert_or_fetch(s, cert_db)
                    if is_new_cert:
                        num_new_results += 1
                        for alt_name in util.stable_uniq(alt_names):
                            alt_db = CertificateAltName()
                            alt_db.cert_id = cert_db.id
                            alt_db.alt_name = alt_name
                            s.add(alt_db)
                        s.flush()
                else:
                    cert_db = cert_existing[fprint]

                all_cert_ids.add(cert_db.id)

                # crt.sh scan info
                if do_job_subres:
                    sub_res_db = DbHandshakeScanJobResult()
                    sub_res_db.scan_id = scan_db.id
                    sub_res_db.job_id = scan_db.job_id
                    sub_res_db.was_new = fprint not in cert_existing
                    sub_res_db.crt_id = cert_db.id
                    sub_res_db.crt_sh_id = cert_db.crt_sh_id
                    sub_res_db.is_ca = cert_db.is_ca
                    s.add(sub_res_db)

                if not cert_db.is_ca:
                    leaf_cert_id = cert_db.id

                prev_id = cert_db.id

            except Exception as e:
                logger.error('Exception when processing a handshake certificate %s' % (e, ))
                self.trace_logger.log(e)

        # path validation test + hostname test
        try:
            validation_res = self.crt_validator.validate(resp.certificates, is_der=True)

            scan_db.valid_path = validation_res.valid
            scan_db.err_many_leafs = len(validation_res.leaf_certs) > 1

            # TODO: error from the validation (timeout, CA, ...)
            scan_db.err_validity = None if validation_res.valid else 'ERR'

            all_valid_alts = TlsDomainTools.get_alt_names(validation_res.valid_leaf_certs)
            matched_domains = TlsDomainTools.match_domain(resp.domain, all_valid_alts)
            scan_db.valid_hostname = len(matched_domains) > 0

        except Exception as e:
            logger.debug('Path validation failed: %s' % e)

        # update main scan result entry
        scan_db.cert_id_leaf = leaf_cert_id
        scan_db.new_results = num_new_results
        scan_db.certs_ids = json.dumps(sorted(util.try_list(all_cert_ids)))
        s.flush()

    def _add_cert_or_fetch(self, s=None, cert_db=None, fetch_first=False):
        """
        Tries to insert new certificate to the DB.
        If fails due to constraint violation (somebody preempted), it tries to load
        certificate with the same fingerprint. If fails, repeats X times.
        :param s:
        :param cert_db:
        :type cert_db: Certificate
        :return:
        """
        close_after_done = False
        if s is None:
            s = self.db.get_session()
            close_after_done = True

        def _close_s():
            if s is None:
                return
            if close_after_done:
                util.silent_close(s)

        for attempt in range(5):
            done = False
            if not fetch_first or attempt > 0:
                try:
                    s.add(cert_db)
                    s.commit()
                    done = True

                except Exception as e:
                    self.trace_logger.log(e, custom_msg='Probably constraint violation')
                    s.rollback()

            if done:
                _close_s()
                return cert_db, 1

            cert = self.cert_load_fprints(s, cert_db.fprint_sha1)
            if cert is not None:
                _close_s()
                return cert, 0

            time.sleep(0.01)
        _close_s()
        raise Error('Could not store / load certificate')

    def connect_analysis(self, s, sys_params, resp, scan_db, domain, port=None, scheme=None, hostname=None):
        """
        Connects to the host, performs simple connection analysis - HTTP connect, HTTPS connect, follow redirects.
        :param s: 
        :param sys_params:
        :param resp:
        :param scan_db:
        :param domain: 
        :param port: 
        :param scheme: 
        :param hostname: 
        :return: 
        """
        # scheme & port setting, params + auto-detection defaults
        scheme, port = TlsDomainTools.scheme_port_detect(scheme, port)
        hostname = util.defval(hostname, domain)

        if scheme not in ['http', 'https']:
            logger.debug('Unsupported connect scheme / port: %s / %s' % (scheme, port))
            return

        # Raw hostname
        test_domain = TlsDomainTools.parse_hostname(hostname)

        # Try raw connect to the tls if the previous failure does not indicate service is not running
        if resp.handshake_failure not in [TlsHandshakeErrors.CONN_ERR, TlsHandshakeErrors.READ_TO]:
            c_url = '%s://%s:%s' % (scheme, test_domain, port)

            # Direct request attempt on the url - analyze Request behaviour, headers.
            r, error = self.tls_scanner.req_connect(c_url, timeout=sys_params['timeout'], allow_redirects=False)
            scan_db.req_https_result = self.tls_scanner.err2status(error)

            # Another request for HSTS & pinning detection without cert verify.
            if error == RequestErrorCode.SSL:
                r, error = self.tls_scanner.req_connect(c_url, timeout=sys_params['timeout'], allow_redirects=False,
                                                        verify=False)
            self.http_headers_analysis(s, scan_db, r)

            r, error = self.tls_scanner.req_connect(c_url, timeout=sys_params['timeout'])
            scan_db.follow_https_result = self.tls_scanner.err2status(error)

            # Load follow URL if there was a SSL error.
            if error == RequestErrorCode.SSL:
                r, error = self.tls_scanner.req_connect(c_url, timeout=sys_params['timeout'], verify=False)

            scan_db.follow_https_url = r.url if error is None else None

        # simple HTTP check - default connection point when there is no scheme
        if port == 443:
            c_url = 'http://%s' % test_domain

            r, error = self.tls_scanner.req_connect(c_url, timeout=sys_params['timeout'])
            scan_db.follow_http_result = self.tls_scanner.err2status(error)

            # Another request without cert verify, follow url is interesting
            if error == RequestErrorCode.SSL:
                r, error = self.tls_scanner.req_connect(c_url, timeout=sys_params['timeout'], verify=False)

            scan_db.follow_http_url = r.url if error is None else None

        s.flush()

    def http_headers_analysis(self, s, scan_db, r):
        """
        HSTS / cert pinning
        :param s:
        :param scan_db:
        :param r:
        :return:
        """
        if r is None:
            return

        hsts = TlsDomainTools.detect_hsts(r)
        pinn = TlsDomainTools.detect_pinning(r)

        scan_db.hsts_present = hsts.enabled
        if hsts.enabled:
            scan_db.hsts_max_age = hsts.max_age
            scan_db.hsts_include_subdomains = hsts.include_subdomains
            scan_db.hsts_preload = hsts.preload

        scan_db.pinning_present = pinn.enabled
        if pinn.enabled:
            scan_db.pinning_report_only = pinn.report_only
            scan_db.pinning_pins = json.dumps(pinn.pins)

    def fetch_new_certs(self, s, job_data, crt_sh_id, index_result, crtsh_query_db, store_res=True):
        """
        Fetches the new cert fro crt.sh, parses, inserts to the db
        :param s: 
        :param job_data: 
        :param crt_sh_id: 
        :param index_result: 
        :param crt.sh scan object: 
        :param store_res: true if to store crt sh result
        :return: cert_db
        :rtype: Tuple[Certificate, DbCrtShQueryResult]
        """
        try:
            response = self.crt_sh_proc.download_crt(crt_sh_id)
            if not response.success:
                logger.debug('Download of %s not successful' % crt_sh_id)
                return None, None

            cert_db = Certificate()
            cert_db.crt_sh_id = crt_sh_id
            cert_db.crt_sh_ca_id = index_result.ca_id
            cert_db.created_at = salch.func.now()
            cert_db.pem = response.result
            cert_db.source = 'crt.sh'
            alt_names = []

            try:
                cert, alt_names = self.parse_certificate(cert_db, pem=str(cert_db.pem))

            except Exception as e:
                cert_db.fprint_sha1 = util.try_sha1_pem(str(cert_db.pem))
                logger.error('Unable to parse certificate %s: %s' % (crt_sh_id, e))
                self.trace_logger.log(e)

            cert_db, is_new = self._add_cert_or_fetch(s, cert_db, fetch_first=True)
            if is_new:
                for alt_name in util.stable_uniq(alt_names):
                    alt_db = CertificateAltName()
                    alt_db.cert_id = cert_db.id
                    alt_db.alt_name = alt_name
                    s.add(alt_db)
                s.commit()

            # crt.sh scan info
            crtsh_res_db = None
            if store_res:
                crtsh_res_db = DbCrtShQueryResult()
                crtsh_res_db.query_id = crtsh_query_db.id
                crtsh_res_db.job_id = crtsh_query_db.job_id
                crtsh_res_db.was_new = 1
                crtsh_res_db.crt_id = cert_db.id
                crtsh_res_db.crt_sh_id = crt_sh_id
                s.add(crtsh_res_db)

            return cert_db, crtsh_res_db

        except Exception as e:
            logger.error('Exception when downloading a certificate %s: %s' % (crt_sh_id, e))
            self.trace_logger.log(e)
        return None, None

    def analyze_cert(self, s, job_data, cert):
        """
        Parses cert result, analyzes - adds to the db
        :param s: 
        :param job_data: 
        :param cert: 
        :return: 
        """

    def update_job_state(self, job_data, state, s=None):
        """
        Updates job state in DB + sends event via redis
        :param job_data: 
        :param state: 
        :param s:
        :type s: SaQuery
        :return:
        """
        s_was_none = s is None
        try:
            if s is None:
                s = self.db.get_session()

            if isinstance(job_data, ScanJob):
                job_data.state = state
                job_data.updated_at = datetime.now()
                job_data = s.merge(job_data)
                s.flush()

            else:
                stmt = salch.update(ScanJob).where(ScanJob.uuid == job_data['uuid'])\
                    .values(state=state, updated_at=salch.func.now())
                s.execute(stmt)
                s.commit()

            # stmt = salch.update(ScanJob).where(ScanJob.uuid == job_data['uuid']).values(state=state)
            # s.execute(stmt)

        except Exception as e:
            logger.error('Scan job state update failed: %s' % e)
            self.trace_logger.log(e)

        finally:
            if s_was_none:
                util.silent_close(s)

        evt_data = {}
        if isinstance(job_data, ScanJob):
            evt_data = {'job': job_data.uuid, 'state': state}
        else:
            evt_data = {'job': job_data['uuid'], 'state': state}

        evt = rh.scan_job_progress(evt_data)
        self.redis_queue.event(evt)

    def try_whois(self, top_domain, attempts=3):
        """
        Whois call on the topdomain, with retry attempts
        :param top_domain:
        :param attempts:
        :return:
        """
        for attempt in range(attempts):
            try:
                res = ph4whois.whois(top_domain)
                return res

            except ph4whois.parser.PywhoisError as pe:
                return None  # not found

            except ph4whois.parser.PywhoisTldError as pe:
                return None  # unknown TLD

            except ph4whois.parser.PywhoisNoWhoisError as pe:
                return None  # no whois server found

            except ph4whois.parser.PywhoisSlowDownError as pe:
                time.sleep(1)
                if attempt + 1 >= attempts:
                    raise

            except Exception as e:
                if attempt + 1 >= attempts:
                    raise

    #
    # DB tools
    #

    def cert_load_existing(self, s, certs_id):
        """
        Loads existing certificates with cert id from the set
        :param s: 
        :param certs_id: 
        :return: 
        """
        ret = {}

        int_list = [int(x) for x in certs_id]
        res = s.query(Certificate.id, Certificate.crt_sh_id).filter(Certificate.crt_sh_id.in_(int_list)).all()
        for cur in res:
            ret[int(cur.crt_sh_id)] = int(cur.id)

        return ret

    def cert_load_fprints(self, s, fprints):
        """
        Load certificate by sha1 fprint
        :param s: 
        :param fprints: 
        :return: 
        """
        was_array = True
        if not isinstance(fprints, types.ListType):
            fprints = [fprints]
            was_array = False

        fprints = util.lower(util.strip(fprints))
        ret = {}

        res = s.query(Certificate) \
            .filter(Certificate.fprint_sha1.in_(list(fprints))).all()

        for cur in res:
            if not was_array:
                return cur

            ret[util.lower(cur.fprint_sha1)] = cur

        return ret if was_array else None

    def load_top_domain(self, s, top_domain, attempts=5):
        """
        Loads or creates a new top domain record.
        :param s:
        :param top_domain:
        :return:
        :rtype Tuple[DbBaseDomain, is_new]
        """
        for attempt in range(attempts):
            try:
                ret = s.query(DbBaseDomain).filter(DbBaseDomain.domain_name == top_domain).first()
                if ret is not None:
                    return ret, 0

            except Exception as e:
                logger.error('Error fetching top domain from DB: %s : %s' % (top_domain, e))
                self.trace_logger.log(e, custom_msg='top domain fetch error')

            # insert attempt now
            try:
                ret = DbBaseDomain()
                ret.domain_name = top_domain
                s.add(ret)
                s.flush()
                return ret, 1

            except Exception as e:
                s.rollback()
                logger.error('Error inserting top domain from DB: %s : %s' % (top_domain, e))
                self.trace_logger.log(e, custom_msg='top domain fetch error')

            time.sleep(0.01)
        raise Error('Could not store / load top domain')

    #
    # Workers - Redis interactive jobs
    #

    def worker_main(self, idx):
        """
        Worker main entry method
        :param idx: 
        :return: 
        """
        self.local_data.idx = idx
        logger.info('Worker %02d started' % idx)

        while self.is_running():
            job = None
            try:
                job = self.job_queue.get(True, timeout=1.0)
            except QEmpty:
                time.sleep(0.1)
                continue

            try:
                # Process job in try-catch so it does not break worker
                logger.info('[%02d] Processing job' % (idx, ))
                jtype, jobj = job
                if jtype == 'redis':
                    self.process_redis_job(jobj)
                else:
                    pass

            except Exception as e:
                logger.error('Exception in processing job %s: %s' % (e, job))
                self.trace_logger.log(e)

            finally:
                self.job_queue.task_done()
        logger.info('Worker %02d terminated' % idx)

    def scan_load_redis_job(self):
        """
        Loads redis job from the queue. Blocking behavior for optimized performance
        :return: 
        """
        job = self.redis_queue.pop(blocking=True, timeout=1)
        if job is None:
            raise QEmpty()

        return job

    def scan_mark_failed_if_exceeds(self, job, max_tries=5):
        """
        Mark the given job as failed if it has exceeded the maximum allowed attempts.
        
        This will likely be because the job previously exceeded a timeout.
        :param job: 
        :param max_tries: 
        :return: 
        """
        mt = job.max_tries()
        if mt is None:
            mt = max_tries

        if mt is None or mt == 0 or job.attempts() <= mt:
            return

        rh.failjob(job)

    def scan_mark_failed_exceeds_attempts(self, job, max_tries=None, e=None):
        """
        Mark the given job as failed if it has exceeded the maximum allowed attempts.
        :param job: 
        :param max_tries: 
        :param e: 
        :return: 
        """
        mt = job.max_tries()
        if mt is None:
            mt = max_tries

        if mt is None or mt == 0 or job.attempts() <= mt:
            return

        rh.failjob(job, e)

    def scan_redis_jobs(self):
        """
        Blocking method scanning redis jobs.
        Should be run in dedicated thread or in the main thread as it blocks the execution. 
        :return: 
        """
        cur_size = self.redis_queue.size()
        logger.info('Redis total queue size: %s' % cur_size)

        while self.is_running():
            job = None
            try:
                job = self.scan_load_redis_job()

            except QEmpty:
                time.sleep(0.01)
                continue

            try:
                self.job_queue.put(('redis', job))

            except Exception as e:
                logger.error('Exception in processing job %s' % (e, ))
                self.trace_logger.log(e)

            finally:
                pass
        logger.info('Queue scanner terminated')

    #
    # DB cleanup
    #

    def cleanup_main(self):
        """
        DB trimming & general cleanup thread
        :return:
        """
        logger.info('Cleanup thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            while not self.stop_event.is_set():
                try:
                    time.sleep(0.2)
                    cur_time = time.time()
                    if self.cleanup_last_check + self.cleanup_check_time > cur_time:
                        continue

                    # TODO: implement
                    self.cleanup_last_check = cur_time

                except Exception as e:
                    logger.error('Exception in DB cleanup: %s' % e)
                    self.trace_logger.log(e)

        except Exception as e:
            logger.error('Exception: %s' % e)
            self.trace_logger.log(e)

        logger.info('Status loop terminated')

    #
    # Server
    #

    def start_daemon(self):
        """
        Starts daemon mode
        :return:
        """
        self.daemon = AppDeamon('/var/run/enigma-keychest-server.pid',
                                stderr=os.path.join(self.logdir, "stderr.log"),
                                stdout=os.path.join(self.logdir, "stdout.log"),
                                app=self)
        self.daemon.start()

    def shutdown_server(self):
        """
        Shutdown flask server
        :return:
        """

    def terminating(self):
        """
        Set state to terminating
        :return:
        """
        self.running = False
        self.stop_event.set()

    def work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('Main thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            # scan redis queue infinitelly
            self.scan_redis_jobs()
            logger.info('Terminating')

            # Wait on all jobs being finished
            self.job_queue.join()

            # All data processed, terminate bored workers
            self.stop_event.set()

            # Make sure it is over by joining threads
            for th in self.workers:
                th.join()

        except Exception as e:
            logger.error('Exception: %s' % e)
            self.trace_logger.log(e)

        self.terminating()
        logger.info('Work loop terminated')

    def work_loop(self):
        """
        Process configuration, initialize connections, databases, start threads.
        :return:
        """
        # Init
        self.init_config()
        self.init_log()
        self.init_db()
        self.init_misc()

        self.cleanup_thread = threading.Thread(target=self.cleanup_main, args=())
        self.cleanup_thread.setDaemon(True)
        self.cleanup_thread.start()

        # Worker start
        for worker_idx in range(0, self.config.workers):
            t = threading.Thread(target=self.worker_main, args=(worker_idx, ))
            self.workers.append(t)
            t.setDaemon(True)
            t.start()

        # periodic worker start
        for worker_idx in range(self.config.periodic_workers):
            t = threading.Thread(target=self.periodic_worker_main, args=(worker_idx,))
            self.watcher_workers.append(t)
            t.setDaemon(True)
            t.start()

        # watcher feeder thread
        self.watcher_thread = threading.Thread(target=self.periodic_feeder_main, args=())
        self.watcher_thread.setDaemon(True)
        self.watcher_thread.start()

        # Daemon vs. run mode.
        if self.args.daemon:
            logger.info('Starting daemon')
            self.start_daemon()

        else:
            # if not self.check_pid():
            #     return self.return_code(1)
            self.work()

    def app_main(self):
        """
        Argument parsing & startup
        :return:
        """
        # Parse our argument list
        parser = argparse.ArgumentParser(description='EnigmaBridge keychest server')

        parser.add_argument('-l', '--pid-lock', dest='pidlock', type=int, default=-1,
                            help='number of attempts for pidlock acquire')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='enables debug mode')

        parser.add_argument('--server-debug', dest='server_debug', default=False, action='store_const', const=True,
                            help='enables server debug mode')

        parser.add_argument('--verbose', dest='verbose', action='store_const', const=True,
                            help='enables verbose mode')

        parser.add_argument('-d', '--daemon', dest='daemon', default=False, action='store_const', const=True,
                            help='Runs in daemon mode')

        parser.add_argument('--ebstall', dest='ebstall', default=False, action='store_const', const=True,
                            help='ebstall compatible mode - uses enigma configuration')

        parser.add_argument('--dump-stats', dest='dump_stats_file', default=None,
                            help='Dumping stats to a file')

        self.args = parser.parse_args()
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work_loop()


def main():
    """
    Main server starter
    :return:
    """
    app = Server()
    app.app_main()


if __name__ == '__main__':
    main()

