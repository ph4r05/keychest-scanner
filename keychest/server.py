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
    DbDnsResolve, DbCrtShQueryInput, \
    DbSubdomainResultCache, DbSubdomainScanBlacklist, DbSubdomainWatchAssoc, DbSubdomainWatchTarget, \
    DbSubdomainWatchResultEntry, DbDnsEntry, DbSubTlsScan, DbLastScanCache, DbWatchService, \
    DbOrganization, DbOrganizationGroup, DbKeychestAgent, \
    ResultModelUpdater, ModelUpdater
import dbutil
from stat_sem import StatSemaphore
from agent import AgentResultPush

from redis_client import RedisClient
from redis_queue import RedisQueue
import redis_helper as rh
from trace_logger import Tracelogger
from tls_handshake import TlsHandshaker, TlsHandshakeResult, TlsIncomplete, TlsTimeout, TlsResolutionError, TlsException, TlsHandshakeErrors
from cert_path_validator import PathValidator, ValidationException, ValidationOsslException, ValidationResult
from tls_domain_tools import TlsDomainTools, TargetUrl
from tls_scanner import TlsScanner, TlsScanResult, RequestErrorCode, RequestErrorWrapper
from errors import Error, InvalidHostname
from server_jobs import JobTypes, BaseJob, PeriodicJob, PeriodicReconJob, ScanResults
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, CrtshInputType, DbLastScanCacheType
import util_cert
from api import RestAPI

import threading
import pid
import socket
import time
import re
import os
import sys
import copy
import types
import util
import math
import json
import base64
import itertools
import argparse
import calendar
import random
from threading import RLock as RLock
import logging
import coloredlogs
import traceback
import collections
import signal
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue
from datetime import datetime, timedelta

import sqlalchemy as salch
from sqlalchemy.orm.query import Query as SaQuery
from sqlalchemy import case, literal_column
from sqlalchemy.orm.session import make_transient

from crt_sh_processor import CrtProcessor, CrtShIndexRecord, CrtShIndexResponse, CrtShException, CrtShTimeoutException
import ph4whois
import requests


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


#
# Servers
#


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
        self.agent_mode = False

        self.db = None
        self.redis = None
        self.redis_queue = None

        self.job_queue = Queue(300)
        self.local_data = threading.local()
        self.workers = []

        self.watch_last_db_scan = 0
        self.watch_db_scan_period = 5
        self.watcher_job_queue_size = 512
        self.watcher_job_queue = PriorityQueue()
        self.watcher_db_cur_jobs = {}  # watchid -> job either in queue or processing
        self.watcher_db_processing = {}  # watchid -> time scan started, protected by lock
        self.watcher_db_lock = RLock()
        self.watcher_workers = []
        self.watcher_thread = None
        self.watcher_job_semaphores = {}  # semaphores for particular tasks

        self.sub_blacklist = {}
        self.sub_blacklist_lock = RLock()

        self.trace_logger = Tracelogger(logger)
        self.crt_sh_proc = CrtProcessor(timeout=8, attempts=2)
        self.tls_handshaker = TlsHandshaker(timeout=5, tls_version='TLS_1_2', attempts=3)
        self.crt_validator = PathValidator()
        self.domain_tools = TlsDomainTools()
        self.tls_scanner = TlsScanner()
        self.test_timeout = 5
        self.api = None

        self.agent_publish_event = threading.Event()  # if set to true publish now
        self.agent_queue = PriorityQueue()  # queue of results to publish

        self.cleanup_last_check = 0
        self.cleanup_check_time = 60
        self.cleanup_thread = None
        self.cleanup_thread_lock = RLock()

        self.randomize_diff_time_fact = 0.15
        self.randomize_feeder_fact = 0.25
        self.delta_dns = timedelta(hours=2)
        self.delta_tls = timedelta(hours=8)
        self.delta_crtsh = timedelta(hours=12)
        self.delta_whois = timedelta(hours=48)
        self.delta_wildcard = timedelta(days=2)

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

        self.agent_mode = self.config.agent_mode
        if self.agent_mode and util.is_empty(self.config.master_endpoint):
            raise ValueError('Master endpoint is required in agent mode')

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
        if self.api:
            self.api.shutdown_server()

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
        elif cmd == 'App\\Jobs\\AutoAddSubsJob':
            self.on_redis_auto_sub_job(job)
        else:
            logger.warning('Unknown job: %s' % cmd)
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
        self.update_scan_job_state(job_data, 'started')
        try:
            s = self.db.get_session()

            # load job object
            job_db = s.query(ScanJob).filter(ScanJob.uuid == job_data['uuid']).first()

            # TODO: scan CT database
            # ...

            # DNS scan
            db_dns, dns_entries = self.scan_dns(s, job_data, domain, job_db)
            s.commit()

            self.update_scan_job_state(job_db, 'dns-done', s)

            # crt.sh scan - only if DNS is correct
            if db_dns and db_dns.status == 1:
                try:
                    self.scan_crt_sh(s, job_data, domain, job_db)
                    s.commit()

                except Exception as e:
                    logger.debug('Exception in UI crtsh scan: %s - %s' % (domain, e))
                    self.trace_logger.log(e)

            self.update_scan_job_state(job_db, 'crtsh-done', s)

            # TODO: search for more subdomains, *.domain, %.domain
            # ...

            # direct host scan
            if db_dns and db_dns.status == 1:
                self.scan_handshake(s, job_data, domain, job_db)
                s.commit()

            self.update_scan_job_state(job_db, 'tls-done', s)

            # whois scan - only if DNS was done correctly
            if db_dns and db_dns.status == 1:
                self.scan_whois(s, job_data, domain, job_db)

            # final commit
            s.commit()

        except Exception as e:
            logger.warning('Scanning job exception: %s' % e)
            self.trace_logger.log(e)

        finally:
            util.silent_close(s)

        self.update_scan_job_state(job_data, 'finished')
        pass

    def on_redis_auto_sub_job(self, job):
        """
        Redis job for auto-add subs
        :param job:
        :return:
        """
        self.augment_redis_scan_job(job)

        job_data = job.decoded['data']['json']
        assoc_id = job_data['id']

        s = None
        try:
            s = self.db.get_session()

            assoc = s.query(DbSubdomainWatchAssoc).filter(DbSubdomainWatchAssoc.id == assoc_id).first()
            if assoc is None:
                return

            self.auto_fill_assoc(s, assoc)
            s.commit()

        except Exception as e:
            logger.warning('Auto add sub job exception: %s' % e)
            self.trace_logger.log(e)

        finally:
            util.silent_close(s)

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
        sys_params['mode'] = JobType.UI

        if scan_type == 'planner':
            sys_params['retry'] = 2
            sys_params['timeout'] = 15  # tls & connect scan
            sys_params['mode'] = JobType.BACKGROUND

        data['sysparams'] = sys_params
        return data

    #
    # Scans
    #

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
        sys_params = job_data['sysparams']
        if not TlsDomainTools.can_connect(domain):
            logger.debug('Domain %s not elligible to handshake' % domain)
            return

        port = int(util.defvalkey(job_data, 'scan_port', 443, take_none=False))
        scheme = util.defvalkey(job_data, 'scan_scheme', None, take_none=False)
        do_connect_analysis = util.defvalkey(job_data, 'dns_ok', True, take_none=False)

        # Simple TLS handshake to the given host.
        # Analyze results, store scan record.
        try:
            resp = None  # type: TlsHandshakeResult
            try:
                resp = self.tls_handshaker.try_handshake(domain, port, scheme=scheme,
                                                         attempts=sys_params['retry'],
                                                         timeout=sys_params['timeout'],
                                                         domain=domain_sni)

            except TlsTimeout as te:
                logger.debug('Scan timeout: %s' % te)
                resp = te.scan_result
            except TlsResolutionError as te:
                logger.debug('Scan resolution errors: %s' % te)
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
            scan_db.is_ipv6 = TlsDomainTools.is_valid_ipv6_address(scan_db.ip_scanned)
            scan_db.tls_ver = resp.tls_version
            scan_db.status = len(resp.certificates) > 0
            scan_db.err_code = resp.handshake_failure
            scan_db.tls_alert_code = resp.alert.desc if resp.alert else None
            scan_db.time_elapsed = time_elapsed
            scan_db.results = len(resp.certificates)
            scan_db.new_results = 0
            if store_job:
                s.add(scan_db)
                s.flush()

            # Certificates processing + cert path validation
            self.process_handshake_certs(s, resp, scan_db, do_job_subres=store_job)

            # Try direct connect with requests, follow urls
            if do_connect_analysis:
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
        stores the results.
        
        :param s: 
        :param job_data: 
        :param query:
        :param job_db:
        :type job_db ScanJob
        :param store_to_db if true results are stored to the database, otherwise just returned.
               Gathered certificates are stored always.

        :return:
        :rtype Tuple[DbCrtShQuery, List[DbCrtShQueryResult]]
        """
        crt_sh = None
        raw_query = self.get_crtsh_text_query(query)
        query_type = self.get_crtsh_query_type(query)

        # wildcard background scan - higher timeout
        scan_kwargs = {}
        if self.get_job_type(job_data) == JobType.BACKGROUND:
            if query_type == CrtshInputType.LIKE_WILDCARD:
                scan_kwargs['timeout'] = 20
            if query_type == CrtshInputType.EXACT:
                scan_kwargs['timeout'] = 10

        try:
            crt_sh = self.crt_sh_proc.query(raw_query, **scan_kwargs)

        except CrtShTimeoutException as tex:
            logger.warning('CRTSH timeout for: %s' % raw_query)
            raise

        if crt_sh is None:
            raise CrtShException('CRTSH returned empty result for %s' % raw_query)

        # existing certificates - have pem
        all_crt_ids = set([int(x.id) for x in crt_sh.results if x is not None and x.id is not None])
        existing_ids = self.cert_load_existing(s, list(all_crt_ids))  # type: dict[int -> int]  # crtsh id -> db id
        existing_ids_set = set(existing_ids.keys())
        new_ids = all_crt_ids - existing_ids_set

        # certificate ids (database IDs)
        certs_ids = list(existing_ids.values())

        # scan record
        crtsh_query_db = DbCrtShQuery()
        crtsh_query_db.created_at = salch.func.now()
        crtsh_query_db.job_id = job_db.id if job_db is not None else None
        crtsh_query_db.status = crt_sh.success
        crtsh_query_db.results = len(all_crt_ids)
        crtsh_query_db.new_results = len(new_ids)

        # input
        db_input, inp_is_new = self.get_crtsh_input(s, query)
        if db_input is not None:
            crtsh_query_db.input_id = db_input.id

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
        for new_crt_id in sorted(list(new_ids), reverse=True)[:500]:
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
        crtsh_query_db.certs_sh_ids = json.dumps(sorted(all_crt_ids))
        crtsh_query_db.newest_cert_id = max(certs_ids) if not util.is_empty(certs_ids) else None
        crtsh_query_db.newest_cert_sh_id = max(all_crt_ids) if not util.is_empty(certs_ids) else None
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
            if last_scan is not None \
                    and last_scan.last_scan_at \
                    and last_scan.last_scan_at > self._diff_time(self.delta_whois, rnd=True):
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
                    scan_db.status = 2
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
                    scan_db.status = 1

            except ph4whois.parser.PywhoisSlowDownError as se:
                scan_db.status = 3
                logger.debug('Whois scan fail - slow down: %s' % se)
                self.trace_logger.log(se, custom_msg='Whois exception')

            except Exception as e:
                scan_db.status = 0
                logger.debug('Whois scan fail: %s' % e)
                self.trace_logger.log(e, custom_msg='Whois exception')

            if store_to_db and scan_db.status != 3:
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
                                         0,
                                         socket.SOCK_STREAM,
                                         socket.IPPROTO_TCP)

            res = []
            for cur in results:
                res.append((cur[0], cur[4][0]))

            scan_db.dns_res = res
            scan_db.dns_status = 1
            scan_db.status = 1
            scan_db.dns = json.dumps(res)
            scan_db.num_res = len(scan_db.dns_res)
            scan_db.num_ipv4 = len([x for x in scan_db.dns_res if x[0] == 2])
            scan_db.num_ipv6 = len([x for x in scan_db.dns_res if x[0] == 10])

        except socket.gaierror as gai:
            logger.debug('GAI error: %s: %s' % (domain, gai))
            scan_db.status = 2
            scan_db.dns_status = 2

        except Exception as e:
            logger.debug('Exception in DNS scan: %s : %s' % (domain, e))
            scan_db.status = 3
            scan_db.dns_status = 3
            self.trace_logger.log(e)

        if store_to_db:
            s.add(scan_db)
            s.flush()
            if job_db is not None:
                job_db.dns_check_id = scan_db.id
                job_db = s.merge(job_db)

        # DNS sub entries
        dns_entries = []
        for idx, tup in enumerate(scan_db.dns_res):
            family, addr = tup
            entry = DbDnsEntry()
            entry.is_ipv6 = family == 10
            entry.is_internal = TlsDomainTools.is_ip_private(addr)
            entry.ip = addr
            entry.res_order = idx
            entry.scan_id = scan_db.id

            dns_entries.append(entry)
            if store_to_db:
                s.add(entry)
        s.flush()

        return scan_db, dns_entries

    #
    # Periodic scanner
    #

    def load_active_watch_targets(self, s, last_scan_margin=300, randomize=True):
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
        :param randomize: randomizes margin +- 25%
        :return:
        """
        q = s.query(
                    DbWatchTarget,
                    salch.func.min(DbWatchAssoc.scan_periodicity).label('min_periodicity'),
                    DbWatchService
        )\
            .select_from(DbWatchAssoc)\
            .join(DbWatchTarget, DbWatchAssoc.watch_id == DbWatchTarget.id)\
            .outerjoin(DbWatchService, DbWatchService.id == DbWatchTarget.service_id)\
            .filter(DbWatchAssoc.deleted_at == None)\
            .filter(DbWatchAssoc.disabled_at == None)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, types.FloatType) else self.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1*fact, fact))
            cur_margin = datetime.now() - timedelta(seconds=last_scan_margin)
            q = q.filter(salch.or_(
                DbWatchTarget.last_scan_at < cur_margin,
                DbWatchTarget.last_scan_at == None
            ))

        return q.group_by(DbWatchTarget.id, DbWatchAssoc.scan_type)\
                .order_by(DbWatchTarget.last_scan_at)  # select the oldest scanned first

    def load_active_recon_targets(self, s, last_scan_margin=300, randomize=True):
        """
        Loads active jobs to scan, from the oldest.
        After loading the result is a tuple (DbSubdomainWatchTarget, min_periodicity).

        :param s : SaQuery query
        :type s: SaQuery
        :param last_scan_margin: margin for filtering out records that were recently processed.
        :param randomize:
        :return:
        """
        q = s.query(
            DbSubdomainWatchTarget,
                    salch.func.min(DbSubdomainWatchAssoc.scan_periodicity).label('min_periodicity')
        )\
            .select_from(DbSubdomainWatchAssoc)\
            .join(DbSubdomainWatchTarget, DbSubdomainWatchAssoc.watch_id == DbSubdomainWatchTarget.id)\
            .filter(DbSubdomainWatchAssoc.deleted_at == None)

        if last_scan_margin:
            if randomize:
                fact = randomize if isinstance(randomize, types.FloatType) else self.randomize_feeder_fact
                last_scan_margin += math.ceil(last_scan_margin * random.uniform(-1*fact, fact))
            cur_margin = datetime.now() - timedelta(seconds=last_scan_margin)
            q = q.filter(salch.or_(
                DbSubdomainWatchTarget.last_scan_at < cur_margin,
                DbSubdomainWatchTarget.last_scan_at == None
            ))

        return q.group_by(DbSubdomainWatchTarget.id, DbSubdomainWatchAssoc.scan_type)\
                .order_by(DbSubdomainWatchTarget.last_scan_at)  # select the oldest scanned first

    def _min_scan_margin(self):
        """
        Computes minimal scan margin from the scan timeouts
        :return:
        """
        return min(self.delta_dns, self.delta_tls, self.delta_crtsh, self.delta_whois).total_seconds()

    def _periodic_queue_is_full(self, for_who=None):
        """
        Returns true if the main watcher queue is full.
        The queue is not strictly bounded to avoid exceptions on re-adding failed
        job to the queue for retry. Method though returns inaccurate results. Used for
        job management.
        :param: for_who:
        :return:
        """
        size = self.watcher_job_queue.qsize()
        limit = self.watcher_job_queue_size

        # make some space for next feeders so it does not starve
        if for_who is not None and for_who == JobTypes.SUB:
            limit += math.ceil(0.1 * limit)

        return size >= limit

    def _periodic_queue_should_add_new(self):
        """
        Returns true if new jobs can be added to the queue.
        :return:
        """
        size = self.watcher_job_queue.qsize()
        return size <= self.watcher_job_queue_size * 0.85

    def periodic_feeder_init(self):
        """
        Initializes data structures required for data processing
        :return:
        """
        num_max_recon = max(self.config.periodic_workers, int(self.config.periodic_workers * 0.2 + 1))
        num_max_watch = max(1, self.config.periodic_workers - 5)  # leave at leas few threads left
        logger.info('Max watch: %s, Max recon: %s' % (num_max_watch, num_max_recon))

        # semaphore array init
        self.watcher_job_semaphores = {
            JobTypes.TARGET: StatSemaphore(num_max_watch),
            JobTypes.SUB: StatSemaphore(num_max_recon)
        }

        # periodic worker start
        for worker_idx in range(self.config.periodic_workers):
            t = threading.Thread(target=self.periodic_worker_main, args=(worker_idx,))
            self.watcher_workers.append(t)
            t.setDaemon(True)
            t.start()

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

            if not scan_now and self.watch_last_db_scan + 2 <= ctime and self._periodic_queue_should_add_new():
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
        if self._periodic_queue_is_full():
            return

        s = self.db.get_session()

        try:
            self._periodic_feeder_watch(s)
            self._periodic_feeder_recon(s)

        finally:
            util.silent_close(s)

    def _periodic_feeder_watch(self, s):
        """
        Load watcher jobs
        :param s:
        :return:
        """
        if self._periodic_queue_is_full():
            return

        try:
            min_scan_margin = self._min_scan_margin()
            query = self.load_active_watch_targets(s, last_scan_margin=min_scan_margin)
            iterator = query.yield_per(100)
            for x in iterator:
                watch_target, min_periodicity, watch_service = x

                if self._periodic_queue_is_full():
                    return

                job = PeriodicJob(target=watch_target, periodicity=min_periodicity, watch_service=watch_service)
                self._periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            s.rollback()
            logger.error('Exception loading watch jobs %s' % e)
            self.trace_logger.log(e)
            raise

    def _periodic_feeder_recon(self, s):
        """
        Load watcher jobs - recon jobs
        :param s:
        :return:
        """
        if self._periodic_queue_is_full(JobTypes.SUB):
            return

        try:
            min_scan_margin = int(self.delta_wildcard.total_seconds())
            query = self.load_active_recon_targets(s, last_scan_margin=min_scan_margin)
            iterator = query.yield_per(100)
            for x in iterator:
                watch_target, min_periodicity = x

                if self._periodic_queue_is_full(JobTypes.SUB):
                    return

                # TODO: analyze if this job should be processed or results are recent, no refresh is needed
                job = PeriodicReconJob(target=watch_target, periodicity=min_periodicity)
                self._periodic_add_job(job)

        except QFull:
            logger.debug('Queue full')
            return

        except Exception as e:
            s.rollback()
            logger.error('Exception loading watch jobs %s' % e)
            self.trace_logger.log(e)
            raise

    def _periodic_add_job(self, job):
        """
        Adds job to the queue
        :param job:
        :return:
        """
        with self.watcher_db_lock:
            # Ignore jobs currently in the progress.
            if job.key() in self.watcher_db_cur_jobs:
                return

            self.watcher_db_cur_jobs[job.key()] = job
            self.watcher_job_queue.put(job)
            logger.debug('Job generated: %s, qsize: %s, sems: %s'
                         % (str(job), self.watcher_job_queue.qsize(), self._periodic_semaphores()))

    def _periodic_semaphores(self):
        """
        Simple state dump on busy threads, returns string
        :return:
        """
        sems = self.watcher_job_semaphores
        return '|'.join(['%s=%s' % (k, sems[k].countinv()) for k in sems])

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
                # logger.debug('[%02d] Processing job' % (idx,))
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
        :type job: BaseJob
        :return:
        """
        sem = self.watcher_job_semaphores[job.type]  # type: StatSemaphore
        sem_acquired = False
        try:
            with self.watcher_db_lock:
                self.watcher_db_processing[job.key()] = job

            sem_acquired = sem.acquire(False)  # simple job type scheduling
            if sem_acquired:
                job.reset_later()
                if job.type == JobTypes.TARGET:
                    self.periodic_process_job_body(job)
                elif job.type == JobTypes.SUB:
                    self.periodic_process_recon_job_body(job)
                else:
                    raise ValueError('Unrecognized job type: %s' % job.type)

        except Exception as e:
            logger.error('Exception in processing watcher job %s' % (e,))
            self.trace_logger.log(e)

        finally:
            remove_job = True
            readd_job = False
            if sem_acquired:
                sem.release()

            # Later? re-enqueue
            if not sem_acquired:
                remove_job = False
                readd_job = True
                job.inclater()

            # if job is success update db last scan value
            elif job.success_scan:
                self.periodic_update_last_scan(job)

            # if retry under threshold, add again to the queue
            elif job.attempts <= 3:
                readd_job = True
                remove_job = False

            # The job has expired.
            # TODO: make sure job does not return quickly by DB load - add backoff / num of fails / last fail
            # remove from processing caches so it can be picked up again later.
            # i.e. remove lock on this item
            if remove_job:
                self.periodic_update_last_scan(job)  # job failed even after many attempts
                with self.watcher_db_lock:
                    del self.watcher_db_cur_jobs[job.key()]

            with self.watcher_db_lock:
                del self.watcher_db_processing[job.key()]

            if readd_job:
                self.watcher_job_queue.put(job)

    def periodic_update_last_scan(self, job):
        """
        Updates last scan time for the job
        :param job:
        :type job: PeriodicJob
        :return:
        """
        if job.type == JobTypes.TARGET:
            self._periodic_update_last_scan_watch(job)
        elif job.type == JobTypes.SUB:
            self._periodic_update_last_scan_recon(job)
        else:
            raise ValueError('Unrecognized job type')

    def _periodic_update_last_scan_watch(self, job):
        """
        Updates watcher job specifically
        :param job:
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

    def _periodic_update_last_scan_recon(self, job):
        """
        Updates watcher job specifically
        :param job:
        :return:
        """
        s = self.db.get_session()
        try:
            stmt = DbSubdomainWatchTarget.__table__.update()\
                .where(DbSubdomainWatchTarget.id == job.target.id)\
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
        logger.debug('Processing watcher job: %s, qsize: %s, sems: %s'
                     % (job, self.watcher_job_queue.qsize(), self._periodic_semaphores()))

        s = None
        url = None

        try:
            url = self.urlize(job)
            if not TlsDomainTools.can_connect(url.host):
                raise InvalidHostname('Invalid host name')

            s = self.db.get_session()
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

        except InvalidHostname as ih:
            logger.debug('Invalid host: %s' % url)
            job.success_scan = True  # TODO: back-off / disable, fatal error

        except Exception as e:
            logger.debug('Exception when processing the watcher job: %s' % e)
            self.trace_logger.log(e)
            job.attempts += 1

        finally:
            util.silent_close(s)

    def periodic_process_recon_job_body(self, job):
        """
        Watcher recon job processing - the body
        :param job:
        :type job: PeriodicReconJob
        :return:
        """
        logger.debug('Processing watcher recon job: %s, qsize: %s, sems: %s'
                     % (job, self.watcher_job_queue.qsize(), self._periodic_semaphores()))
        s = None
        url = None

        try:
            url = self.urlize(job)

            if not TlsDomainTools.can_connect(url.host):
                raise InvalidHostname('Invalid host name')

            s = self.db.get_session()
            self.periodic_scan_subdomain(s, job)
            job.success_scan = True  # updates last scan record

            # each scan can fail independently. Successful scans remain valid.
            if job.scan_crtsh_wildcard.is_failed():
                logger.info('Job failed, wildcard: %s' % (job.scan_crtsh_wildcard.is_failed()))
                job.attempts += 1
                job.success_scan = False

            else:
                job.success_scan = True

        except InvalidHostname as ih:
            logger.debug('Invalid host: %s' % url)
            job.success_scan = True  # TODO: back-off / disable, fatal error
            
        except Exception as e:
            logger.debug('Exception when processing the watcher recon job: %s' % e)
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
        if last_scan is not None \
                and last_scan.last_scan_at \
                and last_scan.last_scan_at > self._diff_time(self.delta_dns, rnd=True):
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
        job_dns = job.scan_dns  # type: ScanResults

        if job.target.agent_id is not None:
            job_scan.skip()  # TLS scan is agent specific
            return

        if util.is_empty(job.ips):
            job_scan.skip()  # DNS is an important part, if watch cannot be resolved - give up.
            return

        prev_scans = self.load_last_tls_scan_last_dns(s, job.watch_id(), job.ips)
        prev_scans_map = {x.ip_scanned: x for x in prev_scans}

        # repeat
        ips_set = set(job.ips)
        scans_to_repeat = list(ips_set - set([x.ip_scanned for x in prev_scans]))  # not scanned yet
        scans_to_repeat += [x.ip_scanned for x in prev_scans
                            if x.ip_scanned != '-' and x.ip_scanned in ips_set
                            and (not x.last_scan_at or x.last_scan_at <= self._diff_time(self.delta_tls, rnd=True))]

        logger.debug('ips: %s, repeat: %s, url: %s, scan map: %s, '
                     % (job.ips, scans_to_repeat, self.urlize(job), prev_scans_map))

        if len(scans_to_repeat) == 0:
            job_scan.skip(prev_scans_map)
            return  # scan is relevant enough

        try:
            for cur_ip in scans_to_repeat:
                self.wp_scan_tls(s, job, prev_scans_map, ip=cur_ip)
            job_scan.ok()

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
        if last_scan is not None \
                and last_scan.last_scan_at \
                and last_scan.last_scan_at > self._diff_time(self.delta_crtsh, rnd=True):
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
        top_domain, is_new = self.load_top_domain(s, top_domain)
        last_scan = self.load_last_whois_scan(s, top_domain) if not is_new else None
        if last_scan is not None \
                and last_scan.last_scan_at \
                and last_scan.last_scan_at > self._diff_time(self.delta_whois, rnd=True):
            job_scan.skip(last_scan)
            return  # scan is relevant enough

        # initiate new whois check
        try:
            self.wp_scan_whois(s=s, job=job, url=url, top_domain=top_domain, last_scan=last_scan)

        except Exception as e:
            job_scan.fail()

            logger.error('Whois exception: %s' % e)
            self.trace_logger.log(e, custom_msg='Whois')

    def periodic_scan_subdomain(self, s, job):
        """
        Periodic CRTsh wildcard scan
        :param job:
        :type job: PeriodicReconJob
        :return:
        """
        job_scan = job.scan_crtsh_wildcard  # type: ScanResults

        # last scan determined by special wildcard query for the watch host
        query, is_new = self.get_crtsh_input(s, job.target.scan_host, 2)
        last_scan = self.load_last_crtsh_wildcard_scan(s, watch_id=job.watch_id(), input_id=query.id)
        if last_scan is not None \
                and last_scan.last_scan_at \
                and last_scan.last_scan_at > self._diff_time(self.delta_wildcard, rnd=True):
            job_scan.skip(last_scan)
            return  # scan is relevant enough

        try:
            self.wp_scan_crtsh_wildcard(s, job, last_scan)

        except Exception as e:
            job_scan.fail()

            logger.error('CRT sh wildcard exception: %s' % e)
            self.trace_logger.log(e, custom_msg='CRT sh wildcard')

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
        data['user_id'] = None

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

        if TlsDomainTools.is_ip(url.host):
            job.primary_ip = url.host
            job.ips = [url.host]
            job_scan.skip()
            return

        if not TlsDomainTools.can_whois(url.host):
            logger.debug('Domain %s not eligible to DNS scan' % url.host)
            job_scan.skip()
            return

        cur_scan, dns_entries = self.scan_dns(s=s, job_data=job_spec, query=url.host, job_db=None, store_to_db=False)
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
            cur_scan.updated_at = salch.func.now()
            cur_scan.last_scan_at = salch.func.now()
            s.add(cur_scan)
            s.flush()

            for entry in dns_entries:
                entry.scan_id = cur_scan.id
                s.add(entry)
            s.flush()
            s.commit()

            # update cached last dns scan id
            stmt = salch.update(DbWatchTarget)\
                .where(DbWatchTarget.id == cur_scan.watch_id)\
                .where(salch.or_(
                    DbWatchTarget.last_dns_scan_id == None,
                    DbWatchTarget.last_dns_scan_id < cur_scan.id)
                ).values(last_dns_scan_id=cur_scan.id)
            s.execute(stmt)
            
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
        self.wp_process_dns(s, job, job_scan.aux)

        # Eventing
        if not is_same_as_before:
            self.on_new_scan(s, old_scan=last_scan, new_scan=cur_scan, job=job)

        # finished with success
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
            job.ips = [x[1] for x in last_scan.dns_res]
        else:
            job.primary_ip = None

    def wp_scan_tls(self, s, job, scan_list, ip=None):
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

        if job.service is not None:
            job_spec['scan_sni'] = job.service.service_name
        elif TlsDomainTools.can_whois(url.host):
            job_spec['scan_sni'] = url.host

        # For now - scan only first IP address in the lexi ordering
        job_spec['dns_ok'] = True
        if ip:
            job_spec['scan_host'] = ip
        elif job.primary_ip:
            job_spec['scan_host'] = job.primary_ip
        else:
            job_scan.skip(scan_list)  # skip TLS handshake check totally if DNS is not valid
            return False

        handshake_res, db_scan = self.scan_handshake(s, job_spec, url.host, None, store_job=False)
        if handshake_res is None:
            return False

        last_scan = util.defvalkey(scan_list, db_scan.ip_scanned, None)

        # Compare with last result, store if new one or update the old one
        is_same_as_before = self.diff_scan_tls(db_scan, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1
            last_scan = s.merge(last_scan)
            s.commit()

        else:
            db_scan.watch_id = job.target.id
            db_scan.num_scans = 1
            db_scan.last_scan_at = salch.func.now()
            db_scan.updated_at = salch.func.now()
            s.add(db_scan)
            s.commit()
            logger.info('TLS scan is different, lastscan: %s for %s' % (last_scan, db_scan.ip_scanned))

            # update last scan cache
            ResultModelUpdater.update_cache(s, db_scan)

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

        # Eventing
        if not is_same_as_before:
            self.on_new_scan(s, old_scan=last_scan, new_scan=db_scan, job=job)

        return True

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
        if crtsh_query_db is None:
            job_scan.fail()
            return

        is_same_as_before = self.diff_scan_crtsh(crtsh_query_db, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1

            if last_scan.input_id is None:  # migration to input ids
                last_scan.input_id = crtsh_query_db.input_id
            last_scan = s.merge(last_scan)
            s.commit()

        else:
            crtsh_query_db.watch_id = job.target.id
            crtsh_query_db.num_scans = 1
            crtsh_query_db.updated_at = salch.func.now()
            crtsh_query_db.last_scan_at = salch.func.now()
            s.add(crtsh_query_db)
            s.commit()

            # update last scan cache
            ResultModelUpdater.update_cache(s, crtsh_query_db)

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

        # Eventing
        if not is_same_as_before:
            self.on_new_scan(s, old_scan=last_scan, new_scan=crtsh_query_db, job=job)

        # finished with success
        job_scan.ok()

    def wp_scan_crtsh_wildcard(self, s, job, last_scan):
        """
        Watcher crt.sh wildcard scan - body
        :param job:
        :type job: PeriodicReconJob
        :param last_scan:
        :type last_scan: DbCrtShQuery
        :return:
        """
        job_scan = job.scan_crtsh_wildcard  # type: ScanResults
        job_spec = self._create_job_spec(job)

        # top domain set?
        self.fix_sub_watch_target_domain(s, job.target)

        # blacklisting check
        if self.is_blacklisted(job.target.scan_host) is not None:
            logger.debug('Domain blacklisted: %s' % job.target.scan_host)
            job_scan.ok()
            return

        # define wildcard & base scan input
        query, is_new = self.get_crtsh_input(s, job.target.scan_host, 2)
        query_base, is_new = self.get_crtsh_input(s, job.target.scan_host, 0)

        # perform crtsh queries, result management
        is_same_as_before_sc, crtsh_query_db, sub_res_list, crtsh_query_db_base, sub_res_list_base = \
            self.wp_scan_wildcard_query(s, query=query, query_base=query_base,
                                        job=job, job_spec=job_spec, last_scan=last_scan)

        # load previous cached result, may be empty.
        last_cache_res = self.load_last_subs_result(s, watch_id=job.watch_id())
        is_same_as_before = is_same_as_before_sc or last_cache_res is None
        db_sub = None

        # new result - store new subdomain data, invalidate old results
        if not is_same_as_before:
            # - extract domains to the result cache....
            # - load previously saved certs, not loaded now, from db
            # TODO: load previous result, just add altnames added in new certificates.
            sub_lists = list(sub_res_list) + list(sub_res_list_base)
            certs_to_load = list(set([x.crt_id for x in sub_lists
                                      if x is not None and x.crt_sh_id is not None and x.cert_db is None]))
            certs_loaded = list(self.cert_load_by_id(s, certs_to_load).values())
            certs_downloaded = [x.cert_db for x in sub_lists
                                if x is not None and x.cert_db is not None]

            all_alt_names = set()
            for cert in (certs_loaded + certs_downloaded):  # type: Certificate
                for alt in cert.all_names:
                    all_alt_names.add(util.lower(alt))

            # - filter out alt names not ending on the target
            suffix = '.%s' % query.iquery
            suffix_alts = set()
            for alt in all_alt_names:
                if alt.endswith(suffix) or alt == query.iquery:
                    suffix_alts.add(alt)

            # Result
            db_sub = DbSubdomainResultCache()
            db_sub.watch_id = job.watch_id()
            db_sub.created_at = salch.func.now()
            db_sub.updated_at = salch.func.now()
            db_sub.last_scan_at = salch.func.now()
            db_sub.last_scan_idx = crtsh_query_db.newest_cert_sh_id
            db_sub.num_scans = 1
            db_sub.scan_type = 1  # crtsh
            db_sub.trans_result = sorted(list(suffix_alts))
            db_sub.result_size = len(db_sub.trans_result)
            db_sub.result = json.dumps(db_sub.trans_result)

            mm = DbSubdomainResultCache
            is_same, db_sub_new, last_scan = \
                ResultModelUpdater.insert_or_update(s, [mm.watch_id, mm.scan_type], [mm.result], db_sub)
            s.commit()

            # update last scan cache
            if not is_same:
                ResultModelUpdater.update_cache(s, db_sub_new)

            # Subdomains insert / update
            self.subs_sync_records(s, job, db_sub_new)

            # Add new watcher targets automatically - depends on the assoc model, if enabled
            self.auto_fill_new_watches(s, job, db_sub)  # returns is_same, obj, last_scan
            # TODO: emit events with event manager.

        # Store scan history
        # hist = DbScanHistory()
        # hist.watch_id = job.target.id
        # hist.scan_type = 20  # crtsh w scan
        # hist.scan_code = 0
        # hist.created_at = salch.func.now()
        # s.add(hist)  # TODO: constraint, cannot insert here
        s.commit()

        # TODO: store gap if there is one
        # - compare last scan with the SLA periodicity. multiple IP addressess make it complicated...

        # Eventing
        if not is_same_as_before:
            self.on_new_scan(s, old_scan=last_cache_res, new_scan=db_sub, job=job)

        # finished with success
        job_scan.ok()

    def wp_scan_whois(self, s, job, url, top_domain, last_scan):
        """
        Watcher whois scan - body
        :param job:
        :type job: PeriodicJob
        :param url:
        :param top_domain:
        :type top_domain: DbBaseDomain
        :param last_scan:
        :type last_scan: DbWhoisCheck
        :return:
        """
        job_scan = job.scan_whois  # type: ScanResults
        job_spec = self._create_job_spec(job)
        url = self.urlize(job)

        scan_db = self.scan_whois(s=s, job_data=job_spec, query=top_domain, job_db=None, store_to_db=False)
        if scan_db.status == 3:  # too fast
            job_scan.fail()
            return

        # Compare with last result, store if new one or update the old one
        is_same_as_before = self.diff_scan_whois(scan_db, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1
            last_scan = s.merge(last_scan)
        else:
            scan_db.watch_id = job.target.id
            scan_db.num_scans = 1
            scan_db.updated_at = salch.func.now()
            scan_db.last_scan_at = salch.func.now()
            s.add(scan_db)

        # top domain assoc
        if job.target.top_domain_id != top_domain.id:
            job.target.top_domain_id = top_domain.id
            s.merge(job.target)
        s.commit()

        # update last scan cache
        if not is_same_as_before:
            ResultModelUpdater.update_cache(s, scan_db)

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

        # Eventing
        if not is_same_as_before:
            self.on_new_scan(s, old_scan=last_scan, new_scan=scan_db, job=job)

        job_scan.ok()

    def wp_scan_wildcard_query(self, s, query, query_base, job, job_spec, last_scan):
        """
        Performs CRTSH queries & compares with previous results, updates the DB info.
        :param s:
        :param query:
        :param query_base:
        :param job:
        :param job_spec:
        :param last_scan:
        :return:
        """

        # crtsh search for base record
        crtsh_query_db_base, sub_res_list_base = self.scan_crt_sh(
            s=s, job_data=job_spec, query=query_base, job_db=None, store_to_db=False)

        # load previous input id scan - for change detection
        last_scan_base = self.load_last_crtsh_wildcard_scan(s, watch_id=job.target.id, input_id=query_base.id)
        is_same_as_before_base = self.diff_scan_crtsh_wildcard(crtsh_query_db_base, last_scan_base)

        if is_same_as_before_base:
            last_scan_base.last_scan_at = salch.func.now()
            last_scan_base.num_scans += 1
            if last_scan_base.input_id is None:  # migration to input ids
                last_scan_base.input_id = crtsh_query_db_base.input_id
            last_scan_base = s.merge(last_scan_base)

        else:
            crtsh_query_db_base.sub_watch_id = job.target.id
            crtsh_query_db_base.num_scans = 1
            crtsh_query_db_base.updated_at = salch.func.now()
            crtsh_query_db_base.last_scan_at = salch.func.now()
            s.add(crtsh_query_db_base)
        s.commit()

        # WILDCARD
        # crtsh search for wildcard
        crtsh_query_db, sub_res_list = self.scan_crt_sh(
            s=s, job_data=job_spec, query=query, job_db=None, store_to_db=False)

        is_same_as_before = self.diff_scan_crtsh_wildcard(crtsh_query_db, last_scan)
        if is_same_as_before:
            last_scan.last_scan_at = salch.func.now()
            last_scan.num_scans += 1
            if last_scan.input_id is None:  # migration to input ids
                last_scan.input_id = crtsh_query_db.input_id
            last_scan = s.merge(last_scan)

        else:
            crtsh_query_db.sub_watch_id = job.target.id
            crtsh_query_db.num_scans = 1
            crtsh_query_db.updated_at = salch.func.now()
            crtsh_query_db.last_scan_at = salch.func.now()
            s.add(crtsh_query_db)

        s.commit()
        return is_same_as_before_base and is_same_as_before, \
               crtsh_query_db, sub_res_list, crtsh_query_db_base, sub_res_list_base

    #
    # Scan Results
    #

    def _res_compare_cols_tls(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
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
        t1, t2 = DbHelper.models_tuples(cur_scan, last_scan, self._res_compare_cols_tls())
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

    def diff_scan_crtsh(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbCrtShQuery
        :param last_scan:
        :type last_scan: DbCrtShQuery
        :return:
        """
        return DbHelper.models_tuples_compare(cur_scan, last_scan, self._res_compare_cols_crtsh())

    def _res_compare_cols_whois(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
        :return:
        """
        m = DbWhoisCheck
        return [m.status, m.registrant_cc, m.registrar, m.registered_at, m.expires_at,
                m.rec_updated_at, m.dns, m.aux]

    def diff_scan_whois(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbWhoisCheck
        :param last_scan:
        :type last_scan: DbWhoisCheck
        :return:
        """
        return DbHelper.models_tuples_compare(cur_scan, last_scan, self._res_compare_cols_whois())

    def _res_compare_cols_dns(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
        :return:
        """
        m = DbDnsResolve
        return [m.status, m.dns]

    def diff_scan_dns(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbDnsResolve
        :param last_scan:
        :type last_scan: DbDnsResolve
        :return:
        """
        return DbHelper.models_tuples_compare(cur_scan, last_scan, self._res_compare_cols_dns())

    def _res_compare_cols_crtsh_wildcard(self):
        """
        Returns list of columns for the result.
        When comparing two different results, these cols should be taken into account.
        :return:
        """
        m = DbCrtShQuery
        return [m.status, m.results, m.newest_cert_sh_id, m.certs_ids]

    def diff_scan_crtsh_wildcard(self, cur_scan, last_scan):
        """
        Checks the previous and current scan for significant differences.
        :param cur_scan:
        :type cur_scan: DbCrtShQuery
        :param last_scan:
        :type last_scan: DbCrtShQuery
        :return:
        """
        return DbHelper.models_tuples_compare(cur_scan, last_scan, self._res_compare_cols_crtsh_wildcard())

    #
    # Scan helpers
    #

    def load_last_tls_scan_last_dns(self, s, watch_id=None, ips=None):
        """
        Loads all previous TLS scans performed against the last DNS scan result set.
        Last scan cache for the given watch_id is used to fetch the results.

        :param s:
        :param watch_id:
        :param ips:
        :return:
        """
        if not isinstance(ips, types.ListType):
            ips = [ips]
        else:
            ips = list(ips)

        sub = s.query(DbLastScanCache.scan_id)\
            .filter(DbLastScanCache.cache_type==0)\
            .filter(DbLastScanCache.scan_type==DbScanType.TLS)\
            .filter(DbLastScanCache.obj_id==watch_id)\
            .filter(DbLastScanCache.aux_key.in_(ips))\
            .subquery('x')
        return s.query(DbHandshakeScanJob).filter(DbHandshakeScanJob.id.in_(sub)).all()

    def load_last_tls_scan(self, s, watch_id=None, ip=None):
        """
        Loads the most recent tls handshake scan result for given watch
        target id and optionally the IP address.
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
        q = s.query(DbCrtShQuery)\
            .filter(DbCrtShQuery.watch_id == watch_id)\
            .filter(DbCrtShQuery.sub_watch_id == None)
        return q.order_by(DbCrtShQuery.last_scan_at.desc()).limit(1).first()

    def load_last_crtsh_wildcard_scan(self, s, watch_id=None, input_id=None):
        """
        Loads the latest crtsh scan for the given watch target id or input_id or both
        :param s:
        :param watch_id:
        :param input_id:
        :return:
        :rtype DbCrtShQuery
        """
        q = s.query(DbCrtShQuery)

        if watch_id is not None:
            q = q.filter(DbCrtShQuery.watch_id == None)\
                 .filter(DbCrtShQuery.sub_watch_id == watch_id)

        if input_id is not None:
            q = q.filter(DbCrtShQuery.input_id == input_id)

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

        q = s.query(DbWhoisCheck).filter(DbWhoisCheck.domain_id == top_domain.id)
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

    def load_last_subs_result(self, s, watch_id=None):
        """
        Loads the latest subs scan results - aggregated form
        :param s:
        :param watch_id:
        :return:
        :rtype DbSubdomainResultCache
        """
        if watch_id is None:
            return None
        q = s.query(DbSubdomainResultCache).filter(DbSubdomainResultCache.watch_id == watch_id)
        return q.order_by(DbSubdomainResultCache.last_scan_at.desc()).limit(1).first()

    #
    # Helpers
    #

    def _diff_time(self, delta=None, days=None, seconds=None, hours=None, rnd=True):
        """
        Returns now - diff time
        :param delta:
        :param days:
        :param seconds:
        :param hours:
        :param rnd:
        :return:
        """
        now = datetime.now()
        ndelta = delta if delta else timedelta(days=days, hours=hours, seconds=seconds)
        if rnd:
            fact = rnd if isinstance(rnd, types.FloatType) else self.randomize_diff_time_fact
            ndelta += timedelta(seconds=(ndelta.total_seconds() * random.uniform(-1*fact, fact)))
        return now - ndelta

    def urlize(self, obj):
        """
        Extracts URL object
        :param obj:
        :return:
        """
        if isinstance(obj, PeriodicJob):
            return obj.url()
        elif isinstance(obj, PeriodicReconJob):
            return TargetUrl(scheme=None, host=obj.target.scan_host, port=None)
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
        cert = None  # type: cryptography.x509.Certificate
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

        cert_db.sig_alg = CertSigAlg.oid_to_const(cert.signature_algorithm_oid)
        cert_db.key_type = util_cert.try_get_key_type(cert.public_key())
        cert_db.key_bit_size = util_cert.try_get_pubkey_size(cert.public_key())

        alt_name_test = list(alt_names)
        if not util.is_empty(cert_db.cname):
            alt_name_test.append(cert_db.cname)

        cert_db.is_cloudflare = len(util_cert.cloudflare_altnames(alt_name_test)) > 0
        cert_db.alt_names_arr = alt_names
        cert_db.alt_names = json.dumps(alt_names)

        return cert

    def process_handshake_certs(self, s, resp, scan_db, do_job_subres=True):
        """
        Processes certificates from the handshake
        :param s: session
        :param resp: tls scan response
        :type resp: TlsHandshakeResult
        :param scan_db: tls db model
        :type scan_db: DbHandshakeScanJob
        :param do_job_subres:
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
                cert = self.parse_certificate(cert_db, der=der)

                local_db.append((cert_db, cert, cert_db.alt_names_arr, der))
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
                sub_res_db = DbHandshakeScanJobResult()
                sub_res_db.scan_id = scan_db.id
                sub_res_db.job_id = scan_db.job_id
                sub_res_db.was_new = fprint not in cert_existing
                sub_res_db.crt_id = cert_db.id
                sub_res_db.crt_sh_id = cert_db.crt_sh_id
                sub_res_db.is_ca = cert_db.is_ca
                sub_res_db.trans_cert = cert_db

                if do_job_subres:
                    s.add(sub_res_db)

                if not cert_db.is_ca:
                    leaf_cert_id = cert_db.id

                prev_id = cert_db.id

                scan_db.trans_sub_res.append(sub_res_db)
                scan_db.trans_certs[cert_db.fprint_sha1] = cert_db

            except Exception as e:
                logger.error('Exception when processing a handshake certificate %s' % (e, ))
                self.trace_logger.log(e)

        # path validation test + hostname test
        try:
            validation_res = self.crt_validator.validate(resp.certificates, is_der=True)  # type: ValidationResult

            scan_db.trans_validation_res = validation_res
            scan_db.valid_path = validation_res.valid
            scan_db.err_many_leafs = len(validation_res.leaf_certs) > 1
            self.add_validation_leaf_error_to_result(validation_res, scan_db)

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
        Automatically commits the transaction before inserting - could fail under high load.
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
                if not attempt == 0:  # insert first, then commit transaction before it may fail.
                    s.commit()
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

    def get_job_type(self, job_data):
        """
        Returns if job is UI or Background
        :param job_data:
        :return:
        """
        if job_data is None or 'sysparams' not in job_data:
            return JobType.UI
        params = job_data['sysparams']
        if 'mode' not in params:
            return JobType.UI
        return params['mode']

    def fetch_new_certs(self, s, job_data, crt_sh_id, index_result, crtsh_query_db, store_res=True):
        """
        Fetches the new cert from crt.sh, parses, inserts to the db
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
                cert = self.parse_certificate(cert_db, pem=str(cert_db.pem))
                alt_names = cert_db.alt_names_arr

            except Exception as e:
                cert_db.fprint_sha1 = util.try_sha1_pem(str(cert_db.pem))
                logger.error('Unable to parse certificate %s: %s' % (crt_sh_id, e))
                self.trace_logger.log(e)

            new_cert = cert_db
            cert_db, is_new = self._add_cert_or_fetch(s, cert_db, fetch_first=True)
            if is_new:
                for alt_name in util.stable_uniq(alt_names):
                    alt_db = CertificateAltName()
                    alt_db.cert_id = cert_db.id
                    alt_db.alt_name = alt_name
                    s.add(alt_db)
                s.commit()
            else:   # cert exists, fill in missing fields if empty
                mm = Certificate
                changes = DbHelper.update_model_null_values(cert_db, new_cert, [
                    mm.crt_sh_id, mm.crt_sh_ca_id, mm.parent_id,
                    mm.key_type, mm.key_bit_size, mm.sig_alg])
                if changes > 0:
                    s.commit()

            # crt.sh scan info
            crtsh_res_db = DbCrtShQueryResult()
            crtsh_res_db.query_id = crtsh_query_db.id
            crtsh_res_db.job_id = crtsh_query_db.job_id
            crtsh_res_db.was_new = 1
            crtsh_res_db.crt_id = cert_db.id
            crtsh_res_db.crt_sh_id = crt_sh_id
            crtsh_res_db.cert_db = cert_db
            if store_res:
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
        return None

    def update_scan_job_state(self, job_data, state, s=None):
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
                logger.debug('Slow down whois warning')
                time.sleep(1.5)
                if attempt + 1 >= attempts:
                    raise

            except Exception as e:
                if attempt + 1 >= attempts:
                    raise

    def get_crtsh_query_type(self, query, default_type=None):
        """
        Determines crtsh query type CrtshInputType
        :param query:
        :param default_type:
        :return:
        """
        if default_type is None:
            default_type = CrtshInputType.EXACT

        query_type = None
        if isinstance(query, DbCrtShQueryInput):
            query_type = query.itype

        elif isinstance(query, types.TupleType):
            query_type = query[1]

        return query_type if query_type is not None else default_type

    def get_crtsh_text_query(self, query, query_type=None):
        """
        Generates CRTSH input query to use from the input object
        :param query:
        :return:
        """
        query_input = None

        if isinstance(query, DbCrtShQueryInput):
            query_input = query.iquery
            if query_type is None:
                query_type = query.itype

        elif isinstance(query, types.TupleType):
            query_input, query_type = query[0], query[1]

        else:
            query_input = query

        if query_type is None or query_type == CrtshInputType.EXACT:
            return str(query_input)
        elif query_type == CrtshInputType.STAR_WILDCARD:
            return '*.%s' % query_input
        elif query_type == CrtshInputType.LIKE_WILDCARD:
            return '%%.%s' % query_input
        elif query_type == CrtshInputType.RAW:
            return str(query_input)
        else:
            raise ValueError('Unknown CRTSH query type %s, input %s' % (query_type, query_input))

    def get_crtsh_input(self, s, query, query_type=None):
        """
        CRTSH loads input
        :param s:
        :param query:
        :param query_type:
        :return: Tuple[DbCrtShQueryInput, Boolean]
        """
        if isinstance(query, DbCrtShQueryInput):
            return query, 0

        query_input = None
        if isinstance(query, types.TupleType):
            query_input, query_type = query[0], query[1]

        else:
            query_input = query
        if query_type is None:
            query_type = 0

        return self.load_crtsh_input(s, query_input, query_type)

    def fix_sub_watch_target_domain(self, s, model):
        """
        If top domain id is not filled in, this fixes it
        :param s:
        :param model:
        :type model: DbSubdomainWatchTarget
        :return:
        """
        if model is None:
            return

        if model.top_domain_id is not None:
            return

        # top domain
        top_domain_obj, is_new = self.try_load_top_domain(s, TlsDomainTools.parse_fqdn(model.scan_host))
        if top_domain_obj is not None:
            model.top_domain_id = top_domain_obj.id
        s.merge(model)

    def is_blacklisted(self, domain):
        """
        Returns true if domain is blacklisted by some blacklist rule
        :param domain:
        :return:
        """
        blcopy = []
        with self.sub_blacklist_lock:
            blcopy = list(self.sub_blacklist)

        for rule in blcopy:
            if rule.rule_type == BlacklistRuleType.SUFFIX:
                if domain.endswith(rule.rule):
                    return rule
            elif rule.rule_type == BlacklistRuleType.MATCH:
                if domain == rule.rule:
                    return rule

        return None

    def get_validation_leaf_error(self, valres):
        """
        Tries to get validation error for leaf certificates from the result
        :param valres:
        :type valres: ValidationResult
        :return:
        """
        if valres is None or valres.leaf_validation is None:
            return None
        errs = valres.leaf_validation.validation_errors
        for idx in errs:
            if errs[idx] is not None:
                return errs[idx]

        return None

    def add_validation_leaf_error_to_result(self, valres, scan_db):
        """
        Adds leaf validation error produced by OSSL certificate validator to the scan results
        :param valres:
        :type valres: ValidationResult
        :param scan_db:
        :type scan_db: DbHandshakeScanJob
        :return:
        """
        err = self.get_validation_leaf_error(valres)
        if err is None or not isinstance(err, ValidationOsslException):
            return

        scan_db.err_valid_ossl_code = err.error_code
        scan_db.err_valid_ossl_depth = err.error_depth

    def subs_sync_records(self, s, job, db_sub):
        """
        Adds / updates DbSubdomainWatchResultEntry
        :param s:
        :param job:
        :type job: PeriodicReconJob
        :param db_sub:
        :type db_sub: DbSubdomainResultCache
        :return:
        """

        # Chunking, paginate on 50 per page
        chunks = util.chunk(db_sub.trans_result, 50)
        for chunk in chunks:
            # Load all subdomains
            subs = self.load_subdomains(s, db_sub.watch_id, chunk)
            existing_domains = set(subs.keys())
            new_domains = set(chunk) - existing_domains

            # Update existing domains
            for cur_name in subs:
                cur_rec = subs[cur_name]  # type: DbSubdomainWatchResultEntry
                cur_rec.last_scan_at = db_sub.last_scan_at
                cur_rec.last_scan_id = db_sub.id
                cur_rec.updated_at = salch.func.now()
                cur_rec.num_scans = cur_rec.num_scans + 1
            s.commit()

            # Add new records
            for new_domain in new_domains:
                nw = DbSubdomainWatchResultEntry()
                nw.watch_id = db_sub.watch_id
                nw.is_wildcard = TlsDomainTools.has_wildcard(new_domain)
                nw.is_internal = 0
                nw.is_long = len(new_domain) > 191
                nw.name = new_domain  # TODO: hash if too long
                nw.name_full = new_domain if nw.is_long else None
                nw.created_at = salch.func.now()
                nw.updated_at = salch.func.now()
                nw.last_scan_at = db_sub.last_scan_at
                nw.first_scan_id = db_sub.id
                nw.last_scan_id = db_sub.id
                s.add(nw)
            s.commit()

    def auto_fill_assoc(self, s, assoc):
        """
        Auto fill sub domains from the association now - using current db content
        :param s:
        :param assoc:
        :type assoc: DbSubdomainWatchAssoc
        :return:
        """
        if not assoc.auto_fill_watches:
            return

        sub_res = self.load_last_subs_result(s, watch_id=assoc.watch_id)  # type: DbSubdomainResultCache
        if sub_res is None or util.is_empty(sub_res.trans_result):
            return

        self.auto_fill_new_watches_for_assoc(s, assoc, sub_res.trans_result)

    def auto_fill_new_watches(self, s, job, db_sub):
        """
        Auto-generates new watches from newly generated domains
        :param s:
        :param job:
        :type job: PeriodicReconJob
        :param db_sub:
        :type db_sub: DbSubdomainResultCache
        :return:
        """

        # load all users having auto load enabled for this one
        assocs = s.query(DbSubdomainWatchAssoc)\
            .filter(DbSubdomainWatchAssoc.watch_id == job.target.id)\
            .filter(DbSubdomainWatchAssoc.auto_fill_watches == 1)\
            .all()

        default_new_watches = {}  # type: dict[str -> DbWatchTarget]
        for assoc in assocs:  # type: DbSubdomainWatchAssoc
            self.auto_fill_new_watches_for_assoc(s, assoc, db_sub.trans_result, default_new_watches)

    def auto_fill_new_watches_for_assoc(self, s, assoc, domain_names, default_new_watches=None):
        """
        Auto-generates new watches from newly generated domains, for one association
        :param s:
        :param assoc:
        :param domain_names:
        :param default_new_watches: cache of loaded watch targets, used when iterating over associations
        :type default_new_watches: dict[str -> DbWatchTarget]
        :return:
        """
        if default_new_watches is None:
            default_new_watches = {}

        # number of already active hosts
        # TODO: either use PHP rest API for this or somehow get common constant config
        num_hosts = self.load_num_active_hosts(s, user_id=assoc.user_id)
        max_hosts = self.config.keychest_max_servers
        if num_hosts >= max_hosts:
            return

        # select all hosts anyhow associated with the host, also deleted.
        # Wont add already present hosts (deleted/disabled doesnt matter)
        res = s.query(DbWatchAssoc, DbWatchTarget) \
            .join(DbWatchTarget, DbWatchAssoc.watch_id == DbWatchTarget.id) \
            .filter(DbWatchAssoc.user_id == assoc.user_id) \
            .all()  # type: list[tuple[DbWatchAssoc, DbWatchTarget]]

        # remove duplicates, extract existing association
        domain_names = util.stable_uniq(domain_names)
        existing_host_names = set([x[1].scan_host for x in res])

        for new_host in domain_names:
            if num_hosts >= max_hosts:
                break

            if new_host in existing_host_names:
                continue

            new_host = TlsDomainTools.parse_fqdn(new_host)
            if new_host in existing_host_names:
                continue

            if not TlsDomainTools.can_connect(new_host):
                continue

            wtarget = None
            if new_host in default_new_watches:
                wtarget = default_new_watches[new_host]
            else:
                wtarget, wis_new = self.load_default_watch_target(s, new_host)
                default_new_watches[new_host] = wtarget
                s.commit()  # if add fails the rollback removes the watch

            # new association
            nassoc = DbWatchAssoc()
            nassoc.user_id = assoc.user_id
            nassoc.watch_id = wtarget.id
            nassoc.updated_at = salch.func.now()
            nassoc.created_at = salch.func.now()
            nassoc.auto_scan_added_at = salch.func.now()

            # race condition with another process may cause this to fail on unique constraint.
            try:
                s.add(nassoc)
                s.commit()

                num_hosts += 1
                existing_host_names.add(new_host)

            except Exception as e:
                logger.debug('Exception when adding auto sub watch: %s' % e)
                self.trace_logger.log(e, custom_msg='Auto add sub watch')
                s.rollback()

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

    def cert_load_by_id(self, s, certs_id):
        """
        Loads certificates by IDs
        :param s:
        :param certs_id:
        :return:
        """
        was_array = True
        if not isinstance(certs_id, types.ListType):
            certs_id = [certs_id]
            was_array = False

        certs_id = [int(x) for x in util.compact(certs_id)]
        ret = {}

        res = s.query(Certificate) \
            .filter(Certificate.id.in_(list(certs_id))).all()

        for cur in res:
            if not was_array:
                return cur

            ret[cur.id] = cur

        return ret if was_array else None

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
            if attempt == 0:
                s.commit()  # commit before insert, race condition may violate constraint
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

    def load_crtsh_input(self, s, domain, query_type=0, attempts=5, **kwargs):
        """
        Loads CRTSH query type from DB or creates a new record
        :param s:
        :param domain:
        :param query_type:
        :param attempts:
        :return
        :rtype tuple[DbCrtShQueryInput, bool]
        """
        for attempt in range(attempts):
            try:
                ret = s.query(DbCrtShQueryInput)\
                    .filter(DbCrtShQueryInput.iquery == domain)\
                    .filter(DbCrtShQueryInput.itype == query_type)\
                    .first()
                if ret is not None:
                    return ret, 0

            except Exception as e:
                logger.error('Error fetching crtsh query from DB: %s-%s : %s' % (domain, query_type, e))
                self.trace_logger.log(e, custom_msg='crtsh input fetch error')

            if attempt == 0:
                s.commit()

            # insert attempt now
            try:
                ret = DbCrtShQueryInput()
                ret.iquery = domain
                ret.itype = query_type
                ret.created_at = salch.func.now()

                # top domain
                top_domain_obj, is_new = self.try_load_top_domain(s, TlsDomainTools.parse_fqdn(domain))
                if top_domain_obj is not None:
                    ret.sld_id = top_domain_obj.id

                s.add(ret)
                s.commit()
                return ret, 1

            except Exception as e:
                s.rollback()
                logger.error('Error inserting crtsh input to DB: %s : %s' % (domain, e))
                self.trace_logger.log(e, custom_msg='crtsh input fetch error')

            time.sleep(0.01)
        raise Error('Could not store / load crtsh input')

    def try_get_top_domain(self, domain):
        """
        try-catched top domain load
        :param domain:
        :return:
        """
        try:
            return TlsDomainTools.get_top_domain(domain)
        except:
            pass

    def try_load_top_domain(self, s, domain):
        """
        Determines top domain & loads / inserts it to the DB
        :param s:
        :param domain:
        :return:
        """
        try:
            if util.is_empty(domain):
                return None, None

            top_domain = TlsDomainTools.get_top_domain(domain)
            if util.is_empty(top_domain):
                return None, None

            top_domain, is_new = self.load_top_domain(s, top_domain)
            return top_domain, is_new

        except:
            return None, None

    def load_default_watch_target(self, s, host, attempts=5):
        """
        Tries to load default watch target (https, 443) or creates a new if does not found
        :param s:
        :param host:
        :param attempts:
        :return:
        """
        for attempt in range(attempts):
            try:
                ret = s.query(DbWatchTarget)\
                    .filter(DbWatchTarget.scan_host == host)\
                    .filter(DbWatchTarget.scan_port == '443')\
                    .filter(DbWatchTarget.scan_scheme == 'https')\
                    .first()
                if ret is not None:
                    return ret, 0

            except Exception as e:
                logger.error('Error fetching DbWatchTarget from DB: %s : %s' % (host, e))
                self.trace_logger.log(e, custom_msg='DbWatchTarget fetch error')

            # insert attempt now
            try:
                ret = DbWatchTarget()
                ret.scan_scheme = 'https'
                ret.scan_port = '443'
                ret.scan_host = host
                ret.created_at = salch.func.now()
                ret.updated_at = salch.func.now()

                # top domain
                top_domain_obj, is_new = self.try_load_top_domain(s, TlsDomainTools.parse_fqdn(host))
                if top_domain_obj is not None:
                    ret.top_domain_id = top_domain_obj.id

                s.add(ret)
                s.flush()
                return ret, 1

            except Exception as e:
                s.rollback()
                logger.error('Error inserting DbWatchTarget to DB: %s : %s' % (host, e))
                self.trace_logger.log(e, custom_msg='DbWatchTarget fetch error')

            time.sleep(0.01)
        raise Error('Could not store / load DbWatchTarget')

    def load_subdomains(self, s, watch_id, subs):
        """
        Tries to load all subdomains with given domain name
        :param s:
        :param watch_id:
        :param subs:
        :return:
        """
        was_array = True
        if subs is not None and not isinstance(subs, types.ListType):
            subs = [subs]
            was_array = False

        q = s.query(DbSubdomainWatchResultEntry)

        if watch_id is not None:
            q = q.filter(DbSubdomainWatchResultEntry.watch_id == watch_id)

        if subs is not None:
            q = q.filter(DbSubdomainWatchResultEntry.name.in_(list(subs)))

        ret = {}
        res = q.all()
        for cur in res:
            if not was_array:
                return cur

            ret[cur.name] = cur

        return ret if was_array else None

    def load_num_active_hosts(self, s, user_id):
        """
        Loads number of active user hosts
        :param s:
        :param user_id:
        :return:
        """
        return DbHelper.get_count(
            s.query(DbWatchAssoc)\
            .filter(DbWatchAssoc.user_id==user_id)\
            .filter(DbWatchAssoc.deleted_at == None)\
            .filter(DbWatchAssoc.disabled_at == None))

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
    # Eventing
    #

    def on_new_scan(self, s, old_scan, new_scan, job=None):
        """
        Event called on a new scan result.
        :param s:
        :param old_scan:
        :param new_scan:
        :param job:
        :return:
        """
        if not self.agent_mode:
            return  # nothing to do in server mode now. Later - recomputation, caching, UI eventing, ...

        psh = AgentResultPush()
        psh.old_scan = DbHelper.clone_model(s, old_scan)
        psh.new_scan = DbHelper.clone_model(s, new_scan)
        DbHelper.detach(s, psh.old_scan)
        DbHelper.detach(s, psh.new_scan)
        psh.job = job

        self.agent_queue.put(psh, False)
        self.agent_publish_event.set()

    #
    # API
    #

    def init_agent(self):
        """
        Initializes agent runtime.
        Also inserts new
        :return:
        """
        if not self.agent_mode:
            return  # just safety check not to do mess in the database

        s = None
        try:
            # insert dummy user for watch association
            s = self.db.get_session()
            self._agent_init_sentinels(s)

            # Start publisher thread
            publish_thread = threading.Thread(target=self.agent_publisher_main, args=())
            publish_thread.setDaemon(True)
            publish_thread.start()

            # Start host sync thread
            host_sync_thread = threading.Thread(target=self.agent_sync_hosts_main, args=())
            host_sync_thread.setDaemon(True)
            host_sync_thread.start()

        finally:
            util.silent_close(s)

    def _agent_init_sentinels(self, s):
        """
        Initializes agent sentinels - DB placeholders
        :return:
        """
        user = s.query(DbUser).filter(DbUser.id == 1).first()
        if user is None:
            user = DbUser()
            user.id = 1
            user.name = 'PLACEHOLDER'
            user.email = 'local@master.net'
            user.created_at = user.updated_at = salch.func.now()
            s.add(user)
            s.commit()

        org = s.query(DbOrganization).filter(DbOrganization.id == 1).first()
        if org is None:
            org = DbOrganization()
            org.id = 1
            org.name = 'PLACEHOLDER'
            org.created_at = org.updated_at = salch.func.now()
            s.add(org)
            s.commit()

    def _agent_request_get(self, url, **kwds):
        """
        GET request to the master
        :param url:
        :param kwds:
        :return:
        """
        return self._agent_request(url, 'get', **kwds)

    def _agent_request_post(self, url, **kwds):
        """
        POST request to the master
        :param url:
        :param kwds:
        :return:
        """
        return self._agent_request(url, 'post', **kwds)

    def _agent_request(self, url, method='get', **kwds):
        """
        Returns
        :param url:
        :param method:
        :param kwds:
        :return:
        """
        headers = kwds.get('headers', {})
        headers['X-Auth-API'] = self.config.master_apikey

        kwds['headers'] = headers
        kwds.setdefault('timeout', 10)

        attempts = kwds.get('attempts', 3)
        for attempt in range(attempts):
            try:
                r = requests.request(method=method, url=self.config.master_endpoint + url, **kwds)
                r.raise_for_status()
                return r

            except Exception as e:
                logger.info('Exception in master request %s: %s' % (url, e))
                if attempt + 1 >= attempts:
                    raise

    def agent_sync_hosts(self, s):
        """
        Syncs hosts with the master by calling get hosts method and syncing
        :param s:
        :return:
        """
        resp = self._agent_request_get(url='/api/v1.0/get_targets')
        targets = resp.json()
        targets = targets['targets']
        self.agent_merge_hosts(s, targets)

    def agent_merge_hosts(self, s, targets):
        """
        Merges loaded hosts from the master
        :return:
        """
        allowed_ids = []
        for target in targets:
            svc = self.agent_svc_to_db(s, target['trans_service'])
            watch = self.agent_watch_to_db(s, target, svc=svc)
            allowed_ids.append(watch.id)

        # load all assocs, insert new ones
        assocs = s.query(DbWatchAssoc).filter(DbWatchAssoc.watch_id.in_(allowed_ids)).all()
        associated_watches = set([x.watch_id for x in assocs])
        watches_to_assoc = list(set(allowed_ids) - associated_watches)
        for wid in watches_to_assoc:
            assoc = DbWatchAssoc()
            assoc.watch_id = wid
            assoc.user_id = 1
            assoc.deleted_at = None
            assoc.disabled_at = None
            assoc.created_at = assoc.updated_at = salch.func.now()
            try:
                s.add(assoc)
            except Exception as e:
                s.rollback()
                logger.warning('Could not add WID: %s: %s' % (wid, e))

        # delete assocs where watch id not in the allowed ids
        stmt = salch.delete(DbWatchAssoc) \
            .where(DbWatchAssoc.watch_id.notin_(allowed_ids))
        s.execute(stmt)
        s.commit()

    def agent_watch_to_db(self, s, watch_json, svc=None, top_domain=None):
        """
        Transforms a watch to a db object
        :param s:
        :param host_json:
        :return:
        """
        if watch_json is None:
            return None

        watch = DbWatchTarget()
        watch.id = watch_json['id']
        watch.scan_host = watch_json['scan_host']
        watch.scan_port = watch_json['scan_port']
        watch.scan_scheme = watch_json['scan_scheme']
        watch.scan_connect = watch_json['scan_connect']
        watch.created_at = salch.func.now()
        if svc is not None:
            watch.service_id = svc.id

        db_watch, is_new = ModelUpdater.load_or_insert(s, watch, [
            DbWatchTarget.id,
            DbWatchTarget.scan_host,
            DbWatchTarget.scan_port,
            DbWatchTarget.scan_scheme,
            DbWatchTarget.scan_connect,
            DbWatchTarget.service_id
        ])
        return db_watch

    def agent_svc_to_db(self, s, svc_json):
        """
        Transforms to an object
        :param svc_json:
        :return:
        """
        if svc_json is None:
            return None

        svc = DbWatchService()
        svc.id = svc_json['id']
        svc.service_name = svc_json['service_name']
        svc.created_at = datetime.fromtimestamp(svc_json['created_at'])
        svc.updated_at = datetime.fromtimestamp(svc_json['updated_at'])
        db_svc, is_new = ModelUpdater.load_or_insert(s, svc, [DbWatchService.service_name])
        return db_svc

    def agent_sync_hosts_main(self):
        """
        Main thread for hosts sync with the master
        :return:
        """
        logger.info('Agent host sync thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            last_sync_check = 0
            while not self.stop_event.is_set():
                try:
                    time.sleep(0.25)
                    cur_time = time.time()
                    if last_sync_check + 10 > cur_time:
                        continue

                    s = None
                    try:
                        s = self.db.get_session()
                        self.agent_sync_hosts(s)
                    finally:
                        util.silent_close(s)

                    last_sync_check = cur_time

                except Exception as e:
                    logger.error('Exception in host sync: %s' % e)
                    self.trace_logger.log(e)
                    last_sync_check = time.time()

        except Exception as e:
            logger.error('Exception: %s' % e)
            self.trace_logger.log(e)

        logger.info('Agent host sync loop terminated')

    def agent_publisher_main(self):
        """
        Main thread publishing results to the master
        :return:
        """
        logger.info('Agent publish thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            last_sync_check = 0
            while not self.stop_event.is_set():
                try:
                    time.sleep(0.25)
                    cur_time = time.time()
                    if last_sync_check + 5 > cur_time and not self.agent_publish_event.is_set():
                        continue

                    s = None
                    try:
                        s = self.db.get_session()
                        self.agent_publish(s)

                    finally:
                        util.silent_close(s)

                    last_sync_check = cur_time

                except Exception as e:
                    logger.error('Exception in publish: %s' % e)
                    self.trace_logger.log(e)

        except Exception as e:
            logger.error('Exception: %s' % e)
            self.trace_logger.log(e)

        logger.info('Agent publish loop terminated')

    def agent_publish(self, s):
        """
        Main publish entry point
        :return:
        """
        # TODO: fetch all last scans from the master, load all scans greater than those provided and publish
        # TODO    missing first. Then process queue with new scans - ignore those already being sent.

        # Queue processing
        self._agent_publish_queue(s)

    def _agent_publish_queue(self, s):
        """
        Processes agents publish queue
        :param s:
        :return:
        """
        self.agent_publish_event.clear()  # reset signal - we are processing already
        job = None  # type: AgentResultPush
        try:
            job = self.agent_queue.get(True, timeout=1.0)
            try:
                self._agent_queue_job(s, job)
            except Exception as e:
                logger.error('Uncaught exception in publish queue process: %s' % e)
                self.trace_logger.log(e, custom_msg='Publish queue process')
            finally:
                self.agent_queue.task_done()
        except QEmpty:
            return

    def _agent_queue_job(self, s, job):
        """
        Processes one agent job for publish
        :param s:
        :param job:
        :type job: AgentResultPush
        :return:
        """
        if job is None:
            return

        try:
            new_scan = job.new_scan
            if not isinstance(new_scan, (DbDnsResolve, DbHandshakeScanJob)):
                return

            new_scan_dict = self.agent_dictize_scan(s, new_scan)
            if new_scan_dict is None:
                return

            scans = [new_scan_dict]
            req = {'scans': scans}
            req_json = util.jsonify(req)

            resp = self._agent_request_post(url='/api/v1.0/new_results', json=req_json)
            logger.debug(resp)

        except Exception as e:
            logger.warning('Could not push, reenqueue: %s' % e)
            self.trace_logger.log(e, custom_msg='publish reenqueue')
            self.agent_queue.put(job)

    def agent_dictize_scan(self, s, obj):
        """
        Converts a scan to a dict serializable over the channel to the master
        :param s:
        :param obj:
        :return:
        """
        def sub_dict(inp):
            return self.agent_dictize_scan(s, inp)

        ret = obj
        if isinstance(obj, DbDnsResolve):
            ret = DbHelper.to_dict(obj)
            ret['dns_res'] = util.defval(util.try_load_json(obj.dns), [])
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, DbHandshakeScanJob):
            cols = DbHandshakeScanJob.__table__.columns + [
                dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_certs'), sub_dict),
                dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_sub_res'), sub_dict)
            ]
            ret = DbHelper.to_dict(obj, cols=cols)
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, Certificate):
            ret = DbHelper.to_dict(obj)
            ret['alt_names_arr'] = util.defval(util.try_load_json(obj.alt_names), [])
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, DbHandshakeScanJobResult):
            cols = DbHandshakeScanJobResult.__table__.columns + [
                dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_cert'), sub_dict),
            ]
            ret = DbHelper.to_dict(obj, cols=cols)
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, DbWatchTarget):
            cols = DbWatchTarget.__table__.columns + [
                dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_service'), sub_dict),
                dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_top_domain'), sub_dict)
            ]
            ret = DbHelper.to_dict(obj, cols=cols)
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, DbWatchService):
            cols = DbWatchService.__table__.columns + [
                dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_top_domain'), sub_dict),
                dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_crtsh_input'), sub_dict)
            ]
            ret = DbHelper.to_dict(obj, cols=cols)
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, DbBaseDomain):
            ret = DbHelper.to_dict(obj)
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, DbCrtShQueryInput):
            ret = DbHelper.to_dict(obj)
            ret['_type'] = obj.__class__.__name__

        elif isinstance(obj, types.ListType):
            ret = [sub_dict(x) for x in obj]

        elif isinstance(obj, types.DictionaryType):
            ret = {str(k): sub_dict(obj[k]) for k in obj}

        return ret

    def agent_on_new_results(self, s, r, results):
        """
        Processes new results from the agent
        :param s:
        :param results:
        :return:
        """
        scans = results['scans']
        for scan in scans:
            if scan['_type'] == 'DbDnsResolve':
                self._agent_process_dns(s, r, scan)
            elif scan['_type'] == 'DbHandshakeScanJob':
                pass
            else:
                logger.warning('Unrecognized publish: %s' % scan['_type'])
                pass  # TODO: unrecognized

    def _agent_process_dns(self, s, r, dns):
        """
        DNS
        :param s:
        :param dns:
        :return:
        """
        last = s.query(DbLastScanCache) \
            .filter(DbLastScanCache.obj_id == dns['watch_id']) \
            .filter(DbLastScanCache.cache_type == DbLastScanCacheType.AGENT_SCAN) \
            .filter(DbLastScanCache.scan_type == DbScanType.DNS) \
            .first()

        if last is not None and last.scan_id >= dns['id']:
            return

        # Insert
        db_dns_orig = DbHelper.to_model(dns, DbDnsResolve)
        db_dns = DbHelper.to_model(dns, DbDnsResolve)

        db_dns.id = None
        db_dns.created_at = salch.func.now()  # TODO: from agent, transform to datetime again, auto
        db_dns.updated_at = salch.func.now()  # TODO: from agent, transform to datetime again, auto
        db_dns.last_scan_at = salch.func.now()  # TODO: from agent, transform to datetime again, auto
        s.add(db_dns)
        s.flush()

        dns_entries = []
        for idx, tup in enumerate(dns['dns_res']):
            family, addr = tup
            entry = DbDnsEntry()
            entry.is_ipv6 = family == 10
            entry.is_internal = TlsDomainTools.is_ip_private(addr)
            entry.ip = addr
            entry.res_order = idx
            entry.scan_id = db_dns.id
            s.add(entry)

        # update cached last dns scan id
        stmt = salch.update(DbWatchTarget) \
            .where(DbWatchTarget.id == db_dns.watch_id) \
            .values(last_dns_scan_id=db_dns.id, last_scan_at=salch.func.now())  # TODO: refactor last scan at
        s.execute(stmt)

        ResultModelUpdater.update_cache(s, db_dns_orig, cache_type=DbLastScanCacheType.AGENT_SCAN)
        ResultModelUpdater.update_cache(s, db_dns, cache_type=DbLastScanCacheType.LOCAL_SCAN)
        s.commit()
        logger.debug('DNS scan added : %s' % db_dns.id)

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

                    self.reload_blacklist()

                    # TODO: clean old RRD records
                    self.cleanup_last_check = cur_time

                except Exception as e:
                    logger.error('Exception in DB cleanup: %s' % e)
                    self.trace_logger.log(e)

        except Exception as e:
            logger.error('Exception: %s' % e)
            self.trace_logger.log(e)

        logger.info('Cleanup loop terminated')

    def reload_blacklist(self):
        """
        Reloads sub-blacklist
        :return:
        """
        s = None
        try:
            s = self.db.get_session()
            blacklist_db = s.query(DbSubdomainScanBlacklist).all()

            with self.sub_blacklist_lock:
                self.sub_blacklist = blacklist_db

        finally:
            util.silent_close(s)

    #
    # Migration
    #

    def migrate_main(self):
        """
        Live data migration to minimize downtime
        :return:
        """

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

    def init_api(self):
        """
        Initializes rest endpoint
        :return:
        """
        self.api = RestAPI()
        self.api.server = self
        self.api.config = self.config
        self.api.db = self.db
        self.api.debug = False  # self.args.debug # reloader does not work outside main thread.
        self.api.start()

    def work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('Main thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))

        # Main working loop depends on the operation mode
        if self.agent_mode:
            self.work_agent_main()
        else:
            self.work_redis_scan_main()

        self.terminating()
        logger.info('Work loop terminated')

    def work_agent_main(self):
        """
        Main agent work loop
        :return:
        """
        while self.is_running():
            time.sleep(0.5)

    def work_redis_scan_main(self):
        """
        Main thread scanning the redis queue for jobs
        :return:
        """
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
        util.monkey_patch_asn1_time()

        self.cleanup_thread = threading.Thread(target=self.cleanup_main, args=())
        self.cleanup_thread.setDaemon(True)
        self.cleanup_thread.start()

        migrate_thread = threading.Thread(target=self.migrate_main, args=())
        migrate_thread.setDaemon(True)
        migrate_thread.start()

        # Worker start
        for worker_idx in range(0, self.config.workers):
            t = threading.Thread(target=self.worker_main, args=(worker_idx, ))
            self.workers.append(t)
            t.setDaemon(True)
            t.start()

        # watcher feeder thread
        self.periodic_feeder_init()
        self.watcher_thread = threading.Thread(target=self.periodic_feeder_main, args=())
        self.watcher_thread.setDaemon(True)
        self.watcher_thread.start()

        # REST server needed only for master mode for now (may be changed in future).
        # Init agent mode if needed.
        if self.agent_mode:
            self.init_agent()
        else:
            self.init_api()

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

