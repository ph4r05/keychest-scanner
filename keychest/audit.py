#!/usr/bin/env python
# -*- coding: utf-8 -*-

from past.builtins import basestring    # pip install future
from past.builtins import long

from threading import Lock as Lock
import json
import collections
import logging
import time
import os
import sys
import traceback
from six import iteritems

from . import util

logger = logging.getLogger(__name__)


class AuditManager(object):
    """
    Handles installer actions auditing
    """

    ROOT_SUBDIR = 'keychest-audit'
    CWD_SUBDIR = 'keychest-audit'

    def __init__(self, audit_file=None, append=False, to_root=False, disabled=False, auto_flush=False,
                 flush_enabled=True, *args, **kwargs):
        self.append = append
        self.audit_file = audit_file
        self.audit_records_buffered = []
        self.audit_lock = Lock()
        self.audit_ctr = 0
        self.to_root = to_root
        self.disabled = disabled
        self.auto_flush = auto_flush
        self.flush_enabled = flush_enabled

        self.secrets = set()
        self.secrets_lock = Lock()

    def _log(self, log):
        """
        Appends audit log to the buffer. Lock protected.
        :param log:
        :return:
        """
        with self.audit_lock:
            if self.disabled:
                return

            self.audit_records_buffered.append(log)
        self._autoflush()

    def _get_root_dir(self):
        """
        Returns logging subdir in /root
        :return:
        """
        return os.path.join('/root', self.ROOT_SUBDIR)

    def _filecheck(self):
        """
        Checks audit file, creates a new one if needed.
        :return:
        """
        if self.audit_file is None:
            if self.to_root:
                self.audit_file = os.path.join(self._get_root_dir(), 'kc-audit.json')
                try:
                    logger.debug('Trying audit file %s' % self.audit_file)
                    util.make_or_verify_dir(self._get_root_dir(), mode=0o700)
                    return self._open_audit_file()
                except (IOError, OSError):
                    pass

            self.audit_file = os.path.join(os.getcwd(), self.CWD_SUBDIR, 'kc-audit.json')
            try:
                logger.debug('Trying audit file %s' % self.audit_file)
                util.make_or_verify_dir(os.path.join(os.getcwd(), self.CWD_SUBDIR), mode=0o700)
                return self._open_audit_file()
            except (IOError, OSError):
                pass

            self.audit_file = os.path.join('/tmp', 'kc-audit.json')
            try:
                logger.debug('Trying audit file %s' % self.audit_file)
                return self._open_audit_file()
            except (IOError, OSError):
                pass

            self.audit_file = os.path.join('/tmp', 'kc-audit-%d.json' % int(time.time()))

        if self.audit_ctr < 1:
            logger.debug('Audit file %s' % self.audit_file)

        return self._open_audit_file()

    def _open_audit_file(self):
        """
        Opens the audit file
        :return:
        """
        if self.audit_ctr == 0 and not self.append:
            fh, backup = util.safe_create_with_backup(self.audit_file, 'a', 0o600)
            self.audit_ctr += 1
            return fh

        self.audit_ctr += 1
        return util.safe_open_append(self.audit_file, 0o600)

    def _autoflush(self):
        if self.auto_flush:
            self.flush()

    def _newlog(self, evt=None):
        log = collections.OrderedDict()
        log['time'] = time.time()
        if evt is not None:
            log['evt'] = evt
        return log

    def _valueize_key(self, key):
        """
        Allows only string keys, numerical keys
        :param key:
        :return:
        """
        if isinstance(key, basestring):
            return key
        if isinstance(key, (bool, int, long, float)):
            return key
        return '%s' % key

    def _valueize(self, value):
        """
        Normalizes value to JSON serializable element.
        Tries to serialize value to JSON, if it fails, it is converted to the string.
        :param value:
        :return:
        """
        if isinstance(value, basestring):
            return value
        if isinstance(value, (bool, int, long, float)):
            return value

        # Try JSON serialize
        try:
            json.dumps(value)
            return value
        except TypeError:
            pass

        # Tuple - convert to list
        if isinstance(value, tuple):
            value = list(value)

        # Special support for lists and dictionaries
        # Preserve type, encode sub-values
        if isinstance(value, list):
            return [self._valueize(x) for x in value]

        elif isinstance(value, dict):
            return {self._valueize_key(key): self._valueize(value[key]) for key in value}

        else:
            return '%s' % value

    def _sec_fix(self, value, secrets=None):
        """
        Replaces secrets withs stars in the value recursively.
        :param value:
        :param secrets:
        :return:
        """
        if value is None:
            return value
        if isinstance(value, (bool, int, long, float)):
            return value

        if secrets is None:
            with self.secrets_lock:
                secrets = list(self.secrets)

        if isinstance(value, basestring):
            for sec in secrets:
                try:
                    value = value.encode('utf-8').replace(sec, '***')
                except UnicodeDecodeError:
                    pass
            return value

        # Tuple - convert to list
        if isinstance(value, tuple):
            value = list(value)

        # Special support for lists and dictionaries
        # Preserve type, encode sub-values
        if isinstance(value, list):
            return [self._sec_fix(x) for x in value]

        elif isinstance(value, dict):
            return {self._valueize_key(key): self._sec_fix(value[key]) for key in value}

        else:
            return value

    def _as_dict(self, cls):
        """
        Serializes class as a dictionary
        :param cls:
        :return:
        """
        try:
            return cls.__dict__
        except:
            return cls

    def _args_to_log_raw(self, log, sensitive_=False, secrets_=None, *args):
        """
        Transforms arguments to the log
        :param log:
        :param args:
        :return:
        """
        if args is None:
            return

        for idx, arg in enumerate(args):
            val = self._valueize(arg)
            if sensitive_:
                val = self._sec_fix(val, secrets=secrets_)

            log['arg%d' % idx] = val

    def _args_to_log(self, log, *args):
        self._args_to_log_raw(log, False, None, *args)

    def _args_to_log_sec(self, log, *args):
        self._args_to_log_raw(log, True, None, *args)

    def _kwargs_to_log_raw(self, log, sensitive_=False, secrets_=None,  **kwargs):
        """
        Translates kwargs to the log entries
        :param log:
        :param kwargs:
        :return:
        """
        if kwargs is None:
            return

        for key, value in iteritems(kwargs):
            val = self._valueize(value)
            if sensitive_:
                val = self._sec_fix(val, secrets=secrets_)

            log[self._valueize_key(key)] = val

    def _kwargs_to_log(self, log, **kwargs):
        self._kwargs_to_log_raw(log, sensitive_=False, secrets_=None, **kwargs)

    def _kwargs_to_log_sec(self, log, **kwargs):
        self._kwargs_to_log_raw(log, sensitive_=True, secrets_=None, **kwargs)

    def fix_val(self, value):
        """
        Fixes value
        :param value:
        :return:
        """
        return self._valueize(value)

    def fix_key(self, key):
        """
        Fixes key for audit
        :param key:
        :return:
        """
        return self._valueize_key(key)

    def fix_secret(self, val):
        """
        Removes secret from the value. Should be called on fix_val result.
        :param val:
        :return:
        """
        return self._sec_fix(val)

    def add_secrets(self, secrets):
        """
        Adds secrets - removed from sensitive logs
        :param secrets:
        :return:
        """
        if not isinstance(secrets, list):
            secrets = [secrets]

        with self.secrets_lock:
            for sec in secrets:
                if sec is None:
                    continue
                self.secrets.add(sec)

    def remove_secrets(self, secrets):
        """
        Removes given secrets
        :param secrets:
        :return:
        """
        if not isinstance(secrets, list):
            secrets = [secrets]

        with self.secrets_lock:
            for sec in secrets:
                if sec is None:
                    continue
                self.secrets.discard(sec)

    def clear_secrets(self):
        """
        Removes all secrets
        :return:
        """
        with self.secrets_lock:
            self.secrets.clear()

    def set_flush_enabled(self, flush_enabled):
        """
        Enables the flush to a file.
        :param flush_enabled:
        :return:
        """
        self.flush_enabled = flush_enabled
        self.flush()

    def flush(self):
        """
        Flushes audit logs to the JSON append only file.
        Routine protected by the lock (no new audit record can be inserted while holding the lock)
        :return:
        """
        with self.audit_lock:
            if self.disabled:
                return
            if not self.flush_enabled:
                return

            try:
                if len(self.audit_records_buffered) == 0:
                    return

                with self._filecheck() as fa:
                    for x in self.audit_records_buffered:
                        fa.write(json.dumps(x) + "\n")
                self.audit_records_buffered = []
            except Exception as e:
                logger.debug(traceback.format_exc())
                logger.error('Exception in audit log dump %s' % e)

    def get_content(self):
        """
        Dumps content of the audit file and returns it as a string.
        :return:
        """
        self.flush()
        with self.audit_lock:
            if self.disabled:
                return []

            if self.audit_file is None or not os.path.exists(self.audit_file):
                return self.audit_records_buffered

            return_json = []
            try:
                with open(self.audit_file, 'r') as fa:
                    lines = fa.readlines()
                    for line in lines:
                        try:
                            return_json.append(json.loads(line))
                        except ValueError:
                            return_json.append(line)

            except Exception as e:
                logger.debug(traceback.format_exc())
                logger.error('Exception in audit log dump %s' % e)

            return_json += self.audit_records_buffered
            return return_json

    def audit_exec(self, cmd, cwd=None, retcode=None, stdout=None, stderr=None, exception=None, exctrace=None, *args, **kwargs):
        """
        Audits command execution
        :param cmd: command
        :param cwd: current working directory
        :param retcode: return code
        :param stdout: standard output
        :param stderr: standard error output
        :param exception: exception
        :param exctrace: exception traceback
        :return:
        """
        log = self._newlog('exec')
        log['cmd'] = self._sec_fix(self._valueize(cmd))
        if cwd is not None:
            log['cwd'] = self._valueize(cwd)
        if retcode is not None:
            log['retcode'] = self._valueize(retcode)
        if stdout is not None:
            log['stdout'] = self._sec_fix(self._valueize(stdout))
        if stderr is not None:
            log['stderr'] = self._sec_fix(self._valueize(stderr))
        if exception is not None:
            log['exception'] = self._valueize(exception)
        if exctrace is not None:
            log['exctrace'] = self._valueize(exctrace)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_copy(self, src, dst, *args, **kwargs):
        """
        Audits file copy
        :param src:
        :param dst:
        :return:
        """
        log = self._newlog('copy')
        log['src'] = self._valueize(src)
        log['dst'] = self._valueize(dst)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_move(self, src, dst, *args, **kwargs):
        """
        Audits file move
        :param src:
        :param dst:
        :return:
        """
        log = self._newlog('move')
        log['src'] = self._valueize(src)
        log['dst'] = self._valueize(dst)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_file_create(self, fname, data=None, chmod=None, *args, **kwargs):
        """
        Audits a file creation
        :param fname:
        :param data:
        :param chmod:
        :return:
        """
        log = self._newlog('fnew')
        log['name'] = fname
        if chmod is not None:
            log['chmod'] = self._valueize(data)
        if data is not None:
            log['data'] = self._valueize(data)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_remove(self, fname, *args, **kwargs):
        self.audit_delete(fname, *args, **kwargs)

    def audit_delete(self, fname, *args, **kwargs):
        """
        Audits file deletion
        :param fname:
        :return:
        """
        log = self._newlog('fdel')
        log['name'] = self._valueize(fname)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_chmod(self, fname, privs=None, recursive=None, *args, **kwargs):
        """
        Change of permissions
        :param fname:
        :param privs:
        :param recursive:
        :return:
        """
        def oct_hlp(x):
            if x is None:
                return None
            if isinstance(x, (int, long)):
                return oct(x)
            return self._valueize(x)

        log = self._newlog('chmod')
        log['name'] = self._valueize(fname)
        log['chmod'] = oct_hlp(privs)
        log['recursive'] = self._valueize(recursive)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_chown(self, fname, user=None, group=None, recursive=None, *args, **kwargs):
        """
        Change of owner
        :param fname:
        :param user:
        :param group:
        :param recursive:
        :return:
        """
        log = self._newlog('chmod')
        log['name'] = self._valueize(fname)
        log['user'] = self._valueize(user)
        log['group'] = self._valueize(group)
        log['recursive'] = self._valueize(recursive)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_file_read(self, fname, data=None, *args, **kwargs):
        """
        File read
        :param fname:
        :param data:
        :return:
        """
        log = self._newlog('fread')
        log['name'] = self._valueize(fname)
        if data is not None:
            log['data'] = self._valueize(data)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_file_write(self, fname, data=None, chmod=None, *args, **kwargs):
        """
        File write
        :param fname:
        :param data:
        :param chmod:
        :return:
        """
        log = self._newlog('fwrite')
        log['name'] = self._valueize(fname)
        if chmod is not None:
            log['chmod'] = self._valueize(data)
        if data is not None:
            log['data'] = self._valueize(data)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_download(self, url, retcode=None, *args, **kwargs):
        """
        Download action
        :param url:
        :param retcode:
        :return:
        """
        log = self._newlog('download')
        log['url'] = self._valueize(url)
        if retcode is not None:
            log['retcode'] = self._valueize(retcode)

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_request(self, url=None, data=None, desc=None, sensitive=False, *args, **kwargs):
        """
        API request (e.g., JSON)
        :param url:
        :param data:
        :param desc:
        :param sensitive:
        :return:
        """
        log = self._newlog('request')
        if url is not None:
            log['url'] = self._valueize(url)
        if desc is not None:
            log['desc'] = self._sec_fix(self._valueize(desc))
        if data is not None:
            log['data'] = self._sec_fix(self._valueize(data))

        self._args_to_log_raw(log, sensitive_=sensitive, secrets_=None, *args)
        self._kwargs_to_log_raw(log, sensitive_=sensitive, secrets_=None, **kwargs)
        self._log(log)

    def audit_exception(self, exception=None, exctrace=None, *args, **kwargs):
        """
        Audits exception
        :param exception:
        :param exctrace:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('exception')
        if exception is not None:
            log['exception'] = self._valueize(exception)
        if exctrace is not None:
            log['exctrace'] = self._valueize(exctrace)

        try:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            log['exc_type'] = self._valueize(exc_type)
            log['exc_value'] = self._valueize(exc_value)

            if exception is None:
                log['exception'] = self._valueize(exc_value)

            if exctrace is None:
                log['exctrace'] = self._valueize(traceback.format_exc())
                log['exctrace_struct'] = self._valueize(traceback.extract_tb(exc_traceback))

            # Last line - fails probably
            log['cause'] = self._audit_exception_cause(exc_value)

        except:
            pass

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def _audit_exception_cause(self, exc_value):
        """
        Audits exception to the log
        :param exc_value:
        :param level:
        :return:
        """
        try:
            sub_log = collections.OrderedDict()
            cause = exc_value.cause

            sub_log['exc_value'] = self._valueize(cause)
            sub_log['exc_type'] = self._valueize(cause.__class__)
            sub_log['cause'] = self._audit_exception_cause(cause)
            return sub_log
        except:
            return None

    def audit_error(self, *args, **kwargs):
        """
        Error auditing
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('error')
        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_print(self, *args, **kwargs):
        """
        Command line auditing - printing
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('print')

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_print_sensitive(self, *args, **kwargs):
        """
        Command line auditing - printing
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('print')
        log['sensitive'] = True

        self._args_to_log_sec(log, *args)
        self._kwargs_to_log_sec(log, **kwargs)
        self._log(log)

    def audit_input_prompt(self, question=None, sensitive=False, *args, **kwargs):
        """
        Command line auditing - printing
        :param question:
        :param sensitive:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('input_prompt')
        if question is not None:
            log['question'] = self._valueize(question)

        self._args_to_log_raw(log, sensitive_=sensitive, secrets_=None, *args)
        self._kwargs_to_log_raw(log, sensitive_=sensitive, secrets_=None, **kwargs)
        self._log(log)

    def audit_input_enter(self, question=None, answer=None, sensitive=False, *args, **kwargs):
        """
        Command line auditing - printing
        :param question:
        :param answer:
        :param sensitive:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('input_prompt')
        if question is not None:
            log['question'] = self._valueize(question)
        if answer is not None:
            log['answer'] = self._sec_fix(self._valueize(answer))
        if sensitive:
            log['sensitive'] = self._valueize(sensitive)

        self._args_to_log_raw(log, sensitive_=sensitive, secrets_=None, *args)
        self._kwargs_to_log_raw(log, sensitive_=sensitive, secrets_=None, **kwargs)
        self._log(log)

    def audit_value(self, key=None, value=None, as_dict=None, sensitive=False, *args, **kwargs):
        """
        Command line auditing - printing
        :param key:
        :param value:
        :param as_dict:
        :param sensitive:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('value')
        if key is not None:
            log['key'] = self._valueize(key)
        if value is not None:
            log['value'] = self._valueize(value)
        if as_dict is not None:
            if not isinstance(as_dict, (dict, list, basestring)):
                log['value'] = self._valueize(self._as_dict(as_dict))
            else:
                log['value'] = self._valueize(as_dict)
        if sensitive:
            log['sensitive'] = self._valueize(sensitive)

        self._args_to_log_raw(log, sensitive_=sensitive, secrets_=None, *args)
        self._kwargs_to_log_raw(log, sensitive_=sensitive, secrets_=None, **kwargs)
        self._log(log)

    def audit_sql(self, sql=None, user=None, res_code=None, result=None, sensitive=False, **kwargs):
        """
        Logging SQL statements.
        :param sql:
        :param user:
        :param res_code:
        :param result:
        :param sensitive:
        :param kwargs:
        :return:
        """
        log = self._newlog('sql')
        if sql is not None:
            log['sql'] = self._sec_fix(self._valueize(sql))
        if user is not None:
            log['user'] = self._valueize(user)
        if res_code is not None:
            log['res_code'] = self._valueize(res_code)
        if result is not None:
            log['result'] = self._sec_fix(self._valueize(result))
        if sensitive:
            log['sensitive'] = self._valueize(sensitive)

        self._kwargs_to_log_raw(log, sensitive_=sensitive, secrets_=None, **kwargs)
        self._log(log)

    def audit_evt(self, evt, *args, **kwargs):
        """
        General audit logging
        :param evt:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog(evt)
        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)



