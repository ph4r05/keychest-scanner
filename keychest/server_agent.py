#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Server agent module

Client mode agent for multi-server deployments

"""
import os
import requests
from past.builtins import cmp
from future.utils import iteritems

import util
from config import Config
from keychest import dbutil
from keychest.agent import AgentResultPush
from keychest.tls_domain_tools import TlsDomainTools
from trace_logger import Tracelogger
from errors import Error, InvalidHostname, ServerShuttingDown, InvalidInputData
from server_jobs import JobTypes, BaseJob, PeriodicJob, ScanResults, PeriodicApiProcessJob
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, CrtshInputType, DbLastScanCacheType, IpType
from server_module import ServerModule
from dbutil import DbApiWaitingObjects, DbApiKey, Certificate, CertificateAltName, DbHelper, DbUser, DbOrganization, \
    DbWatchAssoc, DbWatchTarget, ModelUpdater, DbWatchService, DbDnsResolve, DbHandshakeScanJob, \
    DbHandshakeScanJobResult, DbBaseDomain, DbCrtShQueryInput, DbLastScanCache, ResultModelUpdater, DbDnsEntry, DbOwner
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


class ServerAgent(ServerModule):
    """
    Server API processor
    """

    def __init__(self, *args, **kwargs):
        super(ServerAgent, self).__init__(*args, **kwargs)

        self.trace_logger = Tracelogger(logger)
        self.local_data = threading.local()
        self.agent_publish_event = threading.Event()  # if set to true publish now
        self.agent_queue = PriorityQueue()  # queue of results to publish

    def init(self, server):
        """
        Initializes module with the server
        :param server:
        :return:
        """
        super(ServerAgent, self).init(server=server)

    def run(self):
        """
        Kick off all running threads
        :return:
        """
        super(ServerAgent, self).run()

    def agent_mode(self):
        """
        Returns if in the agent mode
        :return:
        """
        return self.server.agent_mode

    #
    # Agent functions
    #

    def init_agent(self):
        """
        Initializes agent runtime.
        Also inserts new
        :return:
        """
        if not self.agent_mode():
            return  # just safety check not to do mess in the database

        logger.debug('Master endpoint: %s' % self.config.master_endpoint)

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
            util.silent_expunge_all(s)
            util.silent_close(s)

    def agent_on_new_scan(self, s, old_scan, new_scan, job=None):
        """
        Event listener: on new scan finished
        :return:
        """
        psh = AgentResultPush()
        psh.old_scan = DbHelper.clone_model(s, old_scan)
        psh.new_scan = DbHelper.clone_model(s, new_scan)
        DbHelper.detach(s, psh.old_scan)
        DbHelper.detach(s, psh.new_scan)
        psh.job = job

        self.agent_queue.put(psh, False)
        self.agent_publish_event.set()

    def _agent_init_sentinels(self, s):
        """
        Initializes agent sentinels - DB placeholders
        :return:
        """
        owner = s.query(DbOwner).filter(DbOwner.id == 1).first()
        if owner is None:
            owner = DbOwner()
            owner.id = 1
            owner.name = 'PLACEHOLDER'
            owner.created_at = owner.updated_at = salch.func.now()
            s.add(owner)
            s.commit()

        user = s.query(DbUser).filter(DbUser.id == 1).first()
        if user is None:
            user = DbUser()
            user.id = 1
            user.name = 'PLACEHOLDER'
            user.email = 'local@master.net'
            user.primary_owner_id = owner.id
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
            assoc.owner_id = 1
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
        svc.created_at = datetime.datetime.fromtimestamp(svc_json['created_at'])
        svc.updated_at = datetime.datetime.fromtimestamp(svc_json['updated_at'])
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
            while self.is_running():
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
            while self.is_running():
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
                time.sleep(5)  # prevent submitting too fast in case of an error
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
            old_scan = job.old_scan
            if not isinstance(new_scan, (DbDnsResolve, DbHandshakeScanJob)):
                return

            new_scan_dict = self.agent_dictize_scan(s, new_scan)
            if new_scan_dict is None:
                return

            scans = [{'new_scan': new_scan_dict, 'prev_scan_id': None}]
            if old_scan is not None and hasattr(old_scan, 'id'):
                scans['prev_scan_id'] = old_scan.id

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

        elif isinstance(obj, list):
            ret = [sub_dict(x) for x in obj]

        elif isinstance(obj, dict):
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
        for scan_rec in scans:
            scan = scan_rec['new_scan']
            old_scan_id = scan_rec['prev_scan_id']

            if scan['_type'] == 'DbDnsResolve':
                self._agent_process_dns(s, r, scan, old_scan_id)
            elif scan['_type'] == 'DbHandshakeScanJob':
                self._agent_process_tls(s, r, scan, old_scan_id)
            else:
                logger.warning('Unrecognized publish: %s' % scan['_type'])
                pass  # TODO: unrecognized

    def _agent_process_tls(self, s, r, tls, old_scan_id=None):
        """
        TLS
        :param s:
        :param r:
        :param tls:
        :return:
        """
        last = s.query(DbLastScanCache) \
            .filter(DbLastScanCache.obj_id == tls['watch_id']) \
            .filter(DbLastScanCache.cache_type == DbLastScanCacheType.AGENT_SCAN) \
            .filter(DbLastScanCache.scan_type == DbScanType.TLS) \
            .filter(DbLastScanCache.aux_key == tls['ip_scanned']) \
            .first()

        if last is not None and last.scan_id >= tls['id']:
            return

        db_tls_orig = DbHelper.to_model(tls, DbHandshakeScanJob)
        db_tls = DbHelper.to_model(tls, DbHandshakeScanJob, unpack_cols=True)
        db_tls.id = None

        DbHelper.set_if_none(db_tls, val=salch.func.now(), cols=[
            DbHandshakeScanJob.created_at, DbHandshakeScanJob.updated_at, DbHandshakeScanJob.last_scan_at])

        # Certificates... fprint, load, if non existent then create
        loaded_certs = self._agent_proc_certificates(s, r, tls['trans_certs'])  # fprint -> Certificate
        id_to_fprint = {tls['trans_certs'][k]['id']: k for k in tls['trans_certs']}
        id_to_cert = {id: loaded_certs[id_to_fprint[id]] for id in id_to_fprint.keys()}
        id_to_our_id = {id: id_to_cert[id].id for id in id_to_cert.keys()}

        db_tls.cert_id_leaf = id_to_our_id[db_tls.cert_id_leaf] if db_tls.cert_id_leaf is not None else None
        db_tls.certs_ids = util.defval(util.try_load_json(db_tls.certs_ids), [])
        db_tls.certs_ids = json.dumps([id_to_our_id[x] for x in db_tls.certs_ids])
        s.add(db_tls)
        s.flush()

        # Sub res
        for sub_res in tls['trans_sub_res']:
            db_sub = DbHelper.to_model(sub_res, DbHandshakeScanJobResult)
            db_sub.crt_id = id_to_cert[sub_res['crt_id']]
            db_sub.scan_id = db_tls.id
            db_sub.id = None
            s.add(db_sub)
        s.flush()

        # Caches
        ResultModelUpdater.update_cache(s, db_tls_orig, cache_type=DbLastScanCacheType.AGENT_SCAN)
        ResultModelUpdater.update_cache(s, db_tls, cache_type=DbLastScanCacheType.LOCAL_SCAN)
        s.commit()
        logger.debug('TLS scan added : %s IP %s' % (db_tls.id, db_tls.ip_scanned))

    def _agent_proc_certificates(self, s, r, certs):
        """
        Certificate process
        :param s:
        :param r:
        :param certs: fprint->cert map
        :return:
        """
        if certs is None:
            return {}

        fprints = list(certs.keys())
        loaded_fprints = self.server.cert_load_fprints(s, fprints)
        missing_fprints = set(fprints) - set(loaded_fprints.keys())

        for fprint in missing_fprints:
            cert = certs[fprint]

            db_crt_orig = DbHelper.to_model(cert, Certificate)
            db_crt = DbHelper.to_model(cert, Certificate)
            db_crt.id = None
            db_crt.parent_id = None

            db_crt_new, is_new = self.server.add_cert_or_fetch(s, db_crt)
            loaded_fprints[db_crt_new.fprint_sha1] = db_crt_new
            logger.debug('Added agent certificate: %s - %s' % (db_crt.id, db_crt.fprint_sha1))

        return loaded_fprints

    def _agent_process_dns(self, s, r, dns, old_scan_id=None):
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
        db_dns = DbHelper.to_model(dns, DbDnsResolve, unpack_cols=True)
        db_dns.id = None

        DbHelper.set_if_none(db_dns, val=salch.func.now(), cols=[
            DbDnsResolve.created_at, DbDnsResolve.updated_at, DbDnsResolve.last_scan_at])

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
        self.server.update_last_dns_scan_id(s, db_dns)
        self.server.update_watch_last_scan_at(s, db_dns.watch_id)

        ResultModelUpdater.update_cache(s, db_dns_orig, cache_type=DbLastScanCacheType.AGENT_SCAN)
        ResultModelUpdater.update_cache(s, db_dns, cache_type=DbLastScanCacheType.LOCAL_SCAN)
        s.commit()
        logger.debug('DNS scan added : %s' % db_dns.id)





