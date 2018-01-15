#!/usr/bin/env python
# -*- coding: utf-8 -*-

from past.builtins import basestring

import sys
import subprocess
import logging
import traceback

from .audit import AuditManager
from . import errors
from . import util

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class SysConfig(object):
    """Basic system configuration object"""
    SYSCONFIG_BACKUP = '/root/keychest.backup'

    def __init__(self, print_output=False, audit=None, *args, **kwargs):
        self.print_output = print_output
        self.write_dots = False

        self.audit = audit
        if self.audit is None:
            self.audit = AuditManager(disabled=True)

    #
    # Execution
    #

    def exec_shell_open(self, cmd_exec, shell=True, stdin=None, stdout=None, stderr=None):
        """
        Simple execution wrapper with audit logging.
        :param cmd_exec:
        :param shell:
        :param stdin:
        :param stdout:
        :param stderr:
        :return: subprocess
        """
        self.audit.audit_exec(cmd_exec, stdin=stdin, stdout=stdout, stderr=stderr)

        logger.debug('Execute: %s' % cmd_exec)
        p = subprocess.Popen(cmd_exec, shell=shell, stdin=stdin, stdout=stdout, stderr=stderr)
        return p

    def exec_shell_subprocess(self, cmd_exec, shell=True, stdin_string=None):
        """
        Simple execution wrapper with audit logging, executes the command, returns return code.
        Uses subprocess.Popen()
        :param cmd_exec:
        :param shell:
        :param stdin_string: string to pass to the stdin
        :return: return code
        """
        stdin = None if stdin_string is None else subprocess.PIPE
        stdout = None if stdin_string is None else subprocess.PIPE
        stderr = None if stdin_string is None else subprocess.PIPE
        p = self.exec_shell_open(cmd_exec=cmd_exec, shell=shell, stdin=stdin, stdout=stdout, stderr=stderr)

        input = None if stdin_string is None else stdin_string
        sout, serr = p.communicate(input=input)

        self.audit.audit_exec(cmd_exec, retcode=p.returncode, stdout=sout, stderr=serr, stdin_string=stdin_string)
        return p.returncode

    def exec_shell(self, cmd_exec, shell=True, write_dots=None, sensitive=None):
        """
        Simple execution wrapper with audit logging, executes the command, returns return code
        :param cmd_exec:
        :param shell:
        :param write_dots:
        :param sensitive:
        :return: return code
        """
        ret = self.cli_cmd_sync(cmd_exec, shell=shell, write_dots=write_dots)
        return ret[0]

    def cli_cmd_sync(self, cmd, log_obj=None, write_dots=None, on_out=None, on_err=None, cwd=None, shell=True,
                     sensitive=None, readlines=True, env=None, **kwargs):
        """
        Runs command line task synchronously
        :return: ret_code, stdout, stderr
        """
        self.audit.audit_exec(cmd, cwd=cwd)
        logger.debug('Execute: %s' % cmd)

        if write_dots is None:
            write_dots = self.write_dots

        ret = None
        try:
            ret = util.cli_cmd_sync(cmd=cmd, log_obj=log_obj, write_dots=write_dots,
                                    on_out=on_out, on_err=on_err, cwd=cwd, shell=shell, readlines=readlines,
                                    env=env, **kwargs)

            ret_code, out_acc, err_acc = ret
            self.audit.audit_exec(cmd, cwd=cwd, retcode=ret_code, stdout=out_acc, stderr=err_acc)

        except Exception as e:
            self.audit.audit_exec(cmd, cwd=cwd, exception=e, exctrace=traceback.format_exc())
            raise
        return ret

    def print_error(self, msg):
        if self.print_output:
            sys.stderr.write(msg)

    def chown(self, path, user, group):
        """
        Simple chown
        :param path: 
        :param user: string user name / numerical user id / None to leave as is
        :param group: string group name / numerical group id / None to leave as is
        :return: 
        """
        util.chown(path, user, group)
        self.audit.audit_chown(path, user, group, False)

    def chown_recursive(self, path, user, group=None, throw_on_error=False):
        """
        Recursive owner change
        Allows both numerical and string user / groups
        :param path: 
        :param user: string user name / numerical user id / None to leave as is
        :param group: string group name / numerical group id / None to leave as is
        :param throw_on_error: 
        :return: 
        """
        def esc_user(x):
            if isinstance(x, int):
                return x
            return util.escape_shell(x)

        if group is None:
            user_str = '%s' % esc_user(user)
        else:
            user_str = '%s:%s' % (esc_user(user), esc_user(group))

        cmd = 'sudo chown %s -R %s' % (user_str, util.escape_shell(path))
        ret, out, err = self.cli_cmd_sync(cmd)

        self.audit.audit_chown(path, user, group, True)

        if throw_on_error and ret != 0:
            raise errors.OsError('Owner change failed')
        return ret


