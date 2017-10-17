#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key tester
"""

from past.builtins import basestring    # pip install future
from past.builtins import cmp

import util
from config import Config
from redis_queue import RedisQueue
import redis_helper as rh
from trace_logger import Tracelogger
from errors import Error, InvalidHostname, ServerShuttingDown
from server_jobs import JobTypes, BaseJob, PeriodicJob, PeriodicReconJob, PeriodicIpScanJob, ScanResults
from consts import CertSigAlg, BlacklistRuleType, DbScanType, JobType, CrtshInputType, DbLastScanCacheType, IpType
from server_module import ServerModule
from server_data import EmailArtifact, EmailArtifactTypes
import keys_tools

import time
import json
import logging
import threading
import collections
import base64
import imaplib
import email
import email.message as emsg
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue


from M2Crypto import SMIME, X509, BIO

logger = logging.getLogger(__name__)


class KeyTester(ServerModule):
    """
    Key tester server plugin
    """

    def __init__(self, *args, **kwargs):
        super(KeyTester, self).__init__(*args, **kwargs)
        self.redis_queue = None
        self.trace_logger = Tracelogger(logger)

        self.local_data = threading.local()
        self.job_queue = Queue(300)
        self.workers = []

    def init(self, server):
        """
        Initializes module with the server
        :param server:
        :return:
        """
        super(KeyTester, self).init(server=server)
        self.redis_queue = RedisQueue(redis_client=server.redis,
                                      default_queue='queues:tester',
                                      event_queue='queues:tester-evt')

    def shutdown(self):
        """
        Shutdown operation
        :return:
        """
        pass

    def run(self):
        """
        Kick off all running threads
        :return:
        """
        scan_thread = threading.Thread(target=self.scan_redis_jobs, args=())
        scan_thread.setDaemon(True)
        scan_thread.start()

        email_thread = threading.Thread(target=self.main_scan_emails, args=())
        email_thread.setDaemon(True)
        email_thread.start()

        # Worker start
        for worker_idx in range(0, self.config.workers_roca):
            t = threading.Thread(target=self.worker_main, args=(worker_idx,))
            t.setDaemon(True)
            t.start()

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
            logger.info('New job: %s' % json.dumps(keys_tools.shorten_pre_json(job.decoded), indent=2))
            rh.mark_failed_if_exceeds(job)

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

            rh.mark_failed_exceeds_attempts(job, 5, e)
            if not job.is_deleted_or_released() and not job.failed:
                job.release()

    def on_redis_job(self, job):
        """
        Main redis job router. Determines which command should be executed.
        :param job:
        :return:
        """
        payload = job.decoded
        if payload is None or 'data' not in payload:
            logger.warning('Invalid job detected: %s' % json.dumps(payload))
            job.delete()
            return

        data = payload['data']
        cmd = data['commandName']
        if cmd == 'App\\Jobs\\TesterJob':
            self.on_redis_test_job(job)
        else:
            logger.warning('Unknown job: %s' % cmd)
            job.delete()
            return

    def augment_redis_scan_job(self, job=None, data=None):
        """
        Augments job with retry counts, timeouts and so on.
        :param RedisJob job:
        :param data:
        :return:
        """
        if job is not None:
            data = job.decoded['data']['json']

        sys_params = collections.OrderedDict()
        sys_params['retry'] = 2
        sys_params['timeout'] = 20
        sys_params['mode'] = JobType.UI
        data['sysparams'] = sys_params
        return data

    def load_redis_job(self):
        """
        Loads redis job from the queue. Blocking behavior for optimized performance
        :return:
        """
        job = self.redis_queue.pop(blocking=True, timeout=1)
        if job is None:
            raise QEmpty()

        return job

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
                job = self.load_redis_job()

            except QEmpty:
                time.sleep(0.01)
                continue

            try:
                self.job_queue.put(('redis', job))

            except Exception as e:
                logger.error('Exception in processing job %s' % (e,))
                self.trace_logger.log(e)

            finally:
                pass
        logger.info('Queue scanner terminated')

    #
    # Email scanning
    #

    def process_email_job(self, job):
        """
        Processes email job by the worker
        :param job:
        :return:
        """
        logger.debug('Processing email job')

        self.local_data.keys_processed = set()
        email_message, senders, key_parts = job

        results = []
        postponed = []

        # attached keys first
        for part in key_parts:
            if part.ftype & (EmailArtifactTypes.PGP_KEY) != 0:
                res = self.email_pgp_key(part)
                if res is not None:
                    results.append(res)

            else:
                postponed.append(part)

        # again, attached keys are processed, same key used for signature is ignored.
        for part in postponed:
            res = None
            if part.ftype & (EmailArtifactTypes.PKCS7_SIG | EmailArtifactTypes.PKCS7_FILE) != 0:
                res = self.email_pkcs7(part)

            elif part.ftype & (EmailArtifactTypes.PGP_KEY) != 0:
                res = self.email_pgp_key(part)

            elif part.ftype & (EmailArtifactTypes.PGP_SIG) != 0:
                res = self.email_pgp_sign(part)

            else:
                pass

            if res is None or len(res) == 0:
                continue
            results.append(res)

        for res in results:
            out = json.dumps(res, indent=2, cls=util.AutoJSONEncoder)
            if len(out) > 10:
                logger.info(out)

        job = collections.OrderedDict()
        job['jobType'] = 'email'
        job['time'] = time.time()
        job['senders'] = senders
        job['subject'] = email_message.get_all('subject', [])
        job['results'] = results

        evt = rh.tester_job_progress(job)
        self.redis_queue.event(evt)

        # TODO: move email to the DONE folder

    def email_pkcs7(self, key_part):
        """
        Parse PKCS7, get user certificate, parse cert, get user info.

        :param key_part:
        :return:
        """
        try:
            data = key_part.payload
            pkcs7_pem = keys_tools.reformat_pkcs7_pem(data)

            sk = X509.X509_Stack()
            buf = BIO.MemoryBuffer(pkcs7_pem)
            p7 = SMIME.load_pkcs7_bio(buf)

            signers = p7.get0_signers(sk)
            certificate = signers[0]
            cert_der = certificate.as_der()

            cert = util.load_x509_der(cert_der)
            res = collections.OrderedDict()
            res['type'] = 'pkcs7'
            res['fprint_sha256'] = util.lower(util.try_get_fprint_sha256(cert))
            res['cname'] = util.utf8ize(util.try_get_cname(cert))
            res['subject_email'] = util.utf8ize(util.try_get_email(cert))
            res['subject'] = util.utf8ize(util.get_dn_string(cert.subject))
            res['not_before'] = util.unix_time(cert.not_valid_before)

            test_result = self.local_data.fprinter.process_der(cert_der, key_part.filename)
            if test_result is None:
                res['tests'] = None  # processing failed

            res['tests'] = [x.to_json() for x in keys_tools.flatdrop(test_result)]
            return res

        except Exception as e:
            logger.error('Error processing pkcs7: %s' % e)
            self.trace_logger.log(e)

    def email_pgp_key(self, key_part):
        """
        Process PGP public file
        :param key_part:
        :return:
        """
        try:
            data = key_part.payload

            res = collections.OrderedDict()
            res['type'] = 'pgp-key'

            test_result = self.local_data.fprinter.process_pgp(data, key_part.filename)
            if test_result is None:
                res['tests'] = None  # processing failed

            res['tests'] = [x.to_json() for x in keys_tools.flatdrop(test_result)]
            for test in res['tests']:
                if 'kid' in test:
                    self.local_data.keys_processed.add(int(test['kid'], 16))

            return res

        except Exception as e:
            logger.error('Error processing PGP key: %s' % e)
            self.trace_logger.log(e)

    def email_pgp_sign(self, key_part):
        """
        Simple PGP fetch
        :param key_part:
        :return:
        """
        try:
            data = key_part.payload

            res = collections.OrderedDict()
            res['type'] = 'pgp-sign'
            res['results'] = []

            js = keys_tools.process_pgp(data)

            idset = set()
            for x in keys_tools.drop_none([js['master_key_id']] + js['signature_keys']):
                idset.add(x)

            for key in list(idset)[:4]:
                sub = collections.OrderedDict()
                key_data = None

                key_id = keys_tools.strip_hex_prefix(str(key))
                key_id_int = int(key_id, 16)
                if key_id_int in self.local_data.keys_processed:
                    continue

                key_id = keys_tools.format_pgp_key(key_id_int)
                sub['kid'] = key_id
                sub['key_id'] = key_id

                self.get_pgp_id_scan(sub)
                res['results'].append(sub)

                self.local_data.keys_processed.add(key_id_int)
            return res

        except Exception as e:
            logger.error('Error processing PGP key: %s' % e)
            self.trace_logger.log(e)

    def main_scan_emails(self):
        """
        Main thread for scanning email inbox for jobs.
        On job is processed, move email to PROGRESS folder.
        If job is in the progress folder for too long, expire it.
        :return:
        """
        logger.info('Email scanner thread started')
        while self.is_running():
            job = None
            self.server.interruptible_sleep(4)
            try:
                # Load new emails, create job from it
                email_host = self.config.get_config('test_email_host')
                email_name = self.config.get_config('test_email_name')
                email_pass = self.config.get_config('test_email_pass')
                if email_host is None or email_name is None or email_pass is None:
                    continue

                cl = imaplib.IMAP4_SSL(email_host)
                cl.login(email_name, email_pass)

                self.ensure_imap_dirs(cl)
                select_res = cl.select()

                result, data = cl.uid('search', None, 'ALL')  # search and return uids instead
                email_uids = data[0].split()
                if len(email_uids) > 0:
                    logger.debug(email_uids)

                for email_uid in email_uids:
                    try:
                        logger.debug('Fetching: %s' % email_uid)
                        result, data = cl.uid('fetch', email_uid, '(RFC822)')
                        raw_email = data[0][1]

                        email_message = email.message_from_string(raw_email)
                        key_parts = util.flatten(self.look_for_keys(email_message))
                        if len(key_parts) == 0:
                            self.move_mail_to(cl, email_uid, empty=True)
                            continue

                        tos = email_message.get_all('from', [])
                        reply_tos = email_message.get_all('reply-to', [])
                        senders = email.utils.getaddresses(tos + reply_tos)
                        if len(senders) == 0:
                            self.move_mail_to(cl, email_uid, fail=True)
                            continue

                        logger.debug(senders)
                        job = (email_message, senders, key_parts)
                        self.move_mail_to(cl, email_uid, progress=True)

                        self.job_queue.put(('email', job))
                    except Exception as e:
                        logger.error('Exception in processing email %s' % (e,))
                        self.trace_logger.log(e)

            except Exception as e:
                logger.error('Exception in processing job %s' % (e,))
                self.trace_logger.log(e)

            finally:
                self.server.interruptible_sleep(10)

        logger.info('Email scanner terminated')

    def move_mail_to(self, cl, id, done=False, fail=False, empty=False, progress=False):
        """
        Moves email message to.
        :param cl:
        :param id:
        :param to:
        :return:
        """
        to = None
        if done:
            to = 'INBOX.DONE'
        elif fail:
            to = 'INBOX.FAIL'
        elif empty:
            to = 'INBOX.EMPTY'
        elif progress:
            to = 'INBOX.PROGRESS'
        else:
            raise ValueError('Unknown destination folder, have to set at least one flag')

        apply_lbl_msg = cl.uid('COPY', id, to)
        if apply_lbl_msg[0] == 'OK':
            mov, data = cl.uid('STORE', id, '+FLAGS', '(\Deleted)')
            cl.expunge()

    def ensure_imap_dirs(self, cl):
        """
        Ensures all imap dirs are created as they should be.
        :param cl:
        :return:
        """
        status, folders = cl.list()
        has_done = sum([1 for x in folders if '"INBOX.DONE"' in x]) > 0
        has_fail = sum([1 for x in folders if '"INBOX.FAIL"' in x]) > 0
        has_empty = sum([1 for x in folders if '"INBOX.EMPTY"' in x]) > 0
        has_progress = sum([1 for x in folders if '"INBOX.PROGRESS"' in x]) > 0

        if not has_done:
            cl.create('INBOX.DONE')
        if not has_fail:
            cl.create('INBOX.FAIL')
        if not has_empty:
            cl.create('INBOX.EMPTY')
        if not has_progress:
            cl.create('INBOX.PROGRESS')

    def look_for_keys(self, msg):
        """
        Extract interesting portions from the email (pgp keys, pgp signature, pkcs7 signature)
        :param msg:
        :type msg: emsg.Message
        :return:
        """
        ret = []
        if msg.is_multipart():
            for part in msg.get_payload():
                ret.append(self.look_for_keys(part))

        else:
            main_type = msg.get_content_maintype()
            sub_type = msg.get_content_subtype()
            filename = msg.get_filename(None)

            is_pgp_key = main_type == 'application' and sub_type == 'pgp-keys'
            is_pgp_file = filename is not None and (
                filename.endswith('.asc') or filename.endswith('.gpg') or filename.endswith('.pgp')
            )

            is_pgp_sig = main_type == 'application' and sub_type == 'pgp-signature'
            is_pkcs7_sig = main_type == 'application' and sub_type == 'pkcs7-signature'
            is_pkcs7_file = filename is not None and (
                filename.endswith('.p7s')
            )

            logger.debug('%s/%s : %s ; pgp key: %s, pgp file: %s, pgp sig: %s, p7sig: %s, p7file: %s'
                         % (main_type, sub_type, filename, is_pgp_key,
                            is_pgp_file, is_pgp_sig, is_pkcs7_sig, is_pkcs7_file))

            art_type = 0
            art_type |= EmailArtifactTypes.PGP_KEY if is_pgp_key else 0
            art_type |= EmailArtifactTypes.PGP_FILE if is_pgp_file else 0
            art_type |= EmailArtifactTypes.PGP_SIG if is_pgp_sig else 0
            art_type |= EmailArtifactTypes.PKCS7_SIG if is_pkcs7_sig else 0
            art_type |= EmailArtifactTypes.PKCS7_FILE if is_pkcs7_file else 0
            if art_type > 0:
                ret.append(EmailArtifact(filename=filename, ftype=art_type, payload=msg.get_payload(decode=True)))

        return ret

    #
    # Running
    #

    def worker_main(self, idx):
        """
        Worker main entry method - worker thread executes this.
        Processes job_queue jobs, redis enqueued / email queue.

        :param idx:
        :return:
        """
        self.local_data.idx = idx
        self.local_data.fprinter = keys_tools.RocaFingerprinter()
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
                elif jtype == 'email':
                    self.process_email_job(jobj)
                else:
                    pass

            except Exception as e:
                logger.error('Exception in processing job %s: %s' % (e, job))
                self.trace_logger.log(e)

            finally:
                self.job_queue.task_done()
        logger.info('Worker %02d terminated' % idx)

    def on_redis_test_job(self, job):
        """
        Redis job for key test - run in the worker
        :param job:
        :return:
        """
        self.augment_redis_scan_job(job)

        job_data = job.decoded['data']['json']
        keyType = util.lower(util.strip(job_data['keyType']))

        s = None
        try:
            if keyType is None:
                self.on_key(job_data)

            elif keyType == 'file':
                self.on_key(job_data, is_file=True)

            elif keyType == 'github':
                self.on_github_key(job_data)

            elif keyType == 'pgp':
                self.on_pgp_key(job_data)

        except Exception as e:
            logger.warning('Tester job exception: %s' % e)
            self.trace_logger.log(e)

        finally:
            util.silent_close(s)

    def base_job_response(self, job):
        """
        Basic json response skeleton from the job
        :param job:
        :return:
        """
        ret = collections.OrderedDict()
        ret['id'] = job['id']
        ret['time'] = time.time()
        ret['keyType'] = job['keyType']
        ret['keyName'] = job['keyName']
        ret['results'] = []
        return ret

    def on_pgp_key(self, job):
        """
        Pass
        :param job:
        :return:
        """
        res = self.base_job_response(job)

        pgp = util.lower(util.strip(job['pgp']))
        pgp = keys_tools.strip_hex_prefix(pgp)

        if keys_tools.is_pgp_id(pgp):
            key_id = keys_tools.format_pgp_key(int(pgp, 16))
            sub = collections.OrderedDict()
            sub['key_id'] = key_id
            self.get_pgp_id_scan(sub)
            res['results'].append(sub)

        elif keys_tools.is_email_valid(pgp):
            res['results'] += self.get_pgp_email_scan(pgp)

        evt = rh.tester_job_progress(res)
        self.redis_queue.event(evt)

    def on_github_key(self, job):
        """
        github
        :param job:
        :return:
        """
        return self.on_key(job, True)

    def on_key(self, job, ssh=False, is_file=False, **kwargs):
        """
        generic
        :param job:
        :param ssh:
        :param is_file:
        :return:
        """
        res = self.base_job_response(job)
        keys = job['keyValue'] if isinstance(job['keyValue'], list) else [job['keyValue']]

        for idx, key in enumerate(keys):
            key_name = '%s_%d' % (util.defvalkey(job, 'keyName', None), idx)

            if isinstance(key, dict):
                key_name = util.defvalkey(key, 'id', key_name)
                key = util.defvalkey(key, 'key')

            if is_file:
                key = base64.b64decode(key)

            if key is None:
                continue

            key = str(key)
            test_result = None
            if ssh:
                test_result = self.local_data.fprinter.process_ssh(key, key_name)
            else:
                test_result = self.local_data.fprinter.process_file(key, key_name)

            sub = collections.OrderedDict()
            sub['id'] = idx
            sub['tests'] = []

            if test_result is not None:
                sub['tests'] = [x.to_json() for x in keys_tools.flatdrop(test_result)]

            res['results'].append(sub)

        evt = rh.tester_job_progress(res)
        self.redis_queue.event(evt)

    def get_pgp_id_scan(self, sub):
        """
        Fetch PGP key, scan it, return result
        :param sub: sub-result with key_id
        :return:
        """
        try:
            key_data = keys_tools.get_pgp_key(sub['key_id'])
            if key_data is None or len(key_data) == 0:
                raise ValueError('Could not download key')

        except Exception as e:
            sub['error'] = 'key-fetch-error'

            logger.debug('PGP fetch error: %s' % e)
            self.trace_logger.log(e)
            return sub

        try:
            test_result = self.local_data.fprinter.process_pgp(key_data, sub['key_id'])
            sub['tests'] = [x.to_json() for x in list(keys_tools.flatdrop(test_result))]

        except Exception as e:
            sub['error'] = 'key-process-error'
            logger.debug('PGP processing error: %s' % e)
            self.trace_logger.log(e)

        return sub

    def get_pgp_email_scan(self, email):
        """
        Fetch PGP key by email, scan it, return results
        :param email: email
        :return:
        """
        subs = []
        err_sub = collections.OrderedDict()
        err_sub['key_id_resolve_error'] = True
        try:
            key_ids = keys_tools.get_pgp_ids_by_email(email)
            if key_ids is None:
                raise ValueError('Could not resolve email to key ids')

            if len(key_ids) == 0:
                subs.append({'no_keys': True})
                return subs

        except Exception as e:
            err_sub['error'] = 'key-fetch-error'

            logger.debug('PGP error: %s' % e)
            self.trace_logger.log(e)

            subs.append(err_sub)
            return subs

        # Fetch key by key, with limit 5 keys.
        for idx, key_id in enumerate(key_ids):
            sub = collections.OrderedDict()
            sub['idx'] = idx
            sub['key_id'] = key_id
            if idx >= 5:
                sub['limit_reached'] = True
                subs.append(sub)
                continue

            try:
                self.get_pgp_id_scan(sub)

            except Exception as e:
                sub['error'] = 'key-process-error'
                logger.debug('PGP processing: %s' % e)
                self.trace_logger.log(e)

            subs.append(sub)

        return subs

