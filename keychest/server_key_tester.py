#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key tester
"""

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

import time
import json
import logging
import threading
import collections
import imaplib
import email
import email.message as emsg
from queue import Queue, Empty as QEmpty, Full as QFull, PriorityQueue


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
        for worker_idx in range(0, self.config.workers):
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
            logger.info('New job: %s' % json.dumps(job.decoded, indent=4))
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
        # TODO: parse smime pkcs7 signature - there is a cert in it.

        # TODO: parse PGP key and signature - already done by the tester.
        # TODO:     here may be useful to extract the identity, for the report.

        # TODO: analyze email contents
        # TODO: fingerprint SMIME / PGP
        # TODO: send email with the results
        # TODO: move email to the DONE folder

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
                        senders = email.utils.getaddresses(reply_tos + tos)
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
                self.server.interruptible_sleep(60)

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

        # TODO: extract info to test
        job_data = job.decoded['data']['json']
        assoc_id = job_data['id']

        s = None
        try:
            # TODO: do the test
            # TODO: pass the result of the test in the event
            pass
            # s = self.db.get_session()
            #
            # assoc = s.query(DbSubdomainWatchAssoc).filter(DbSubdomainWatchAssoc.id == assoc_id).first()
            # if assoc is None:
            #     return

            # self.auto_fill_assoc(s, assoc)
            # s.commit()

        except Exception as e:
            logger.warning('Tester job exception: %s' % e)
            self.trace_logger.log(e)

        finally:
            util.silent_close(s)

