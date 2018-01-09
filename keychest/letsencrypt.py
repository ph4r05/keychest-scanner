#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import os
import sys
from datetime import datetime

from . import util

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


LE_PRIVATE_KEY = 'privkey.pem'
LE_CERT = 'cert.pem'
LE_CA = 'fullchain.pem'


class LetsEncrypt(object):
    """
    LetsEncrypt integration
    """

    PORT = 443
    CERTBOT_PATH = 'epiper certbot'
    LE_CERT_PATH = '/etc/letsencrypt/live'
    CERTBOT_LOG = '/tmp/certbot.log'
    PRIVATE_KEY = LE_PRIVATE_KEY
    CERT = LE_CERT
    CA = LE_CA
    FALLBACK_EMAIL = 'letsencrypt_support@enigmabridge.com'

    def __init__(self, email=None, domains=None, print_output=False, staging=False, debug=False, config=None,
                 **kwargs):
        self.email = email
        self.domains = domains
        self.print_output = print_output
        self.staging = staging
        self.debug = debug
        self.config = config

        self.config_dir = kwargs.get('config_dir')
        self.work_dir = kwargs.get('work_dir')
        self.log_dir = kwargs.get('log_dir')
        self.webroot_dir = kwargs.get('webroot_dir')

    def cli_cmd_sync(self, *args, **kwargs):
        """
        Executes the command.
        :param args: 
        :param kwargs: 
        :return: 
        """
        return util.cli_cmd_sync(*args, **kwargs)

    def certonly(self, email=None, domains=None, expand=False, force=False, auto_webroot=False, **kwargs):
        """
        Calls certbot certonly command.
        Used in the intial certbot enrollment. 
        Uses standalone authentication.
        
        :param email: 
        :param domains: 
        :param expand: 
        :param force: 
        :param auto_webroot:
        :return:
        """
        if email is not None:
            self.email = email
        if domains is not None:
            self.domains = domains

        email = self.email
        if (self.email is None or len(self.email) == 0) \
                and self.FALLBACK_EMAIL is not None and len(self.FALLBACK_EMAIL) > 0:
            email = self.FALLBACK_EMAIL

        webroot = None
        if auto_webroot and not self.webroot_dir:
            raise ValueError('Auto webroot needs to have webroot configured')
        if auto_webroot:
            webroot = os.path.join(self.webroot_dir, self.domains[0])
            util.makedirs(webroot)

        cmd = self.get_standalone_cmd(self.domains, email=email,
                                      expand=expand,
                                      staging=self.staging,
                                      break_certs=self.staging,
                                      force=force,
                                      webroot=webroot,
                                      config_dir=self.config_dir,
                                      work_dir=self.work_dir,
                                      log_dir=self.log_dir,
                                      **kwargs)

        cmd_exec = '%s %s' % (self.CERTBOT_PATH, cmd)
        log_obj = self.CERTBOT_LOG

        ret, out, err = self.cli_cmd_sync(cmd_exec, log_obj=log_obj, write_dots=self.print_output)
        if ret != 0:
            self.print_error('\nCertbot command failed: %s\n' % cmd_exec)
            self.print_error('For more information please refer to the log file: %s' % log_obj)

        return ret, out, err

    def renew(self):
        """
        Calls certbot renew.
        Certbot tries to renew all domains in its configuration
        :return: 
        """
        cmd = self.get_renew_cmd()
        cmd_exec = '%s %s' % (self.CERTBOT_PATH, cmd)
        log_obj = self.CERTBOT_LOG

        ret, out, err = self.cli_cmd_sync(cmd_exec, log_obj=log_obj, write_dots=self.print_output)
        if ret != 0 and self.print_output:
            self.print_error('\nCertbot command failed: %s\n' % cmd_exec)
            self.print_error('For more information please refer to the log file: %s' % log_obj)

        return ret, out, err

    def get_cert_path(self):
        """
        /live directory
        :return:
        """
        if self.work_dir is not None:
            return os.path.join(self.config_dir, 'live')
        return self.LE_CERT_PATH

    def get_certificate_dir(self, domain=None):
        """
        Returns path to the certificate directory - live/ directory.
        If domain is not None, returns path to the directory with certificates for the given domain.
        :param domain: 
        :return: 
        """
        if domain is None:
            return self.get_cert_path()
        else:
            return os.path.join(self.get_cert_path(), domain)

    def get_cert_paths(self, cert_dir=None, domain=None):
        """
        Returns files for the given domain
        :param cert_dir: 
        :param domain: 
        :return: privkey_file, cert_file, ca_file
        """
        if domain is not None:
            cert_dir = self.get_certificate_dir(domain)
        if cert_dir is None:
            raise ValueError('Either cert_dir or domain has to be filled')

        priv_file = os.path.join(cert_dir, self.PRIVATE_KEY)
        cert_file = os.path.join(cert_dir, self.CERT)
        ca_file = os.path.join(cert_dir, self.CA)
        return priv_file, cert_file, ca_file

    def is_certificate_ready(self, cert_dir=None, domain=None):
        """
        Checks if the given domain exists and all required files exist as well (privkey, cert, fullchain).
        :param cert_dir: 
        :param domain: 
        :return: 
        """
        priv_file, cert_file, ca_file = self.get_cert_paths(cert_dir=cert_dir, domain=domain)
        if not os.path.exists(priv_file):
            return 1
        elif not os.path.exists(cert_file):
            return 2
        elif not os.path.exists(ca_file):
            return 3
        else:
            return 0

    def test_certificate_for_renew(self, cert_dir=None, domain=None, renewal_before=60*60*24*30):
        """
        Tries to load PEM certificate and check not after
        
        :param cert_dir: 
        :param domain: 
        :param renewal_before: 
        :return: 
        """
        priv_file, cert_file, ca_file = self.get_cert_paths(cert_dir=cert_dir, domain=domain)
        if not os.path.exists(cert_file):
            return 1

        try:
            x509_pem = None
            with open(cert_file, 'r') as hnd:
                x509_pem = hnd.read()

            if x509_pem is None or len(x509_pem) == 0:
                return 2

            x509 = util.load_x509(x509_pem)
            if x509 is None:
                return 3

            not_after = x509.not_valid_after
            utc_now = datetime.utcnow()

            # Already expired?
            if not_after <= utc_now:
                return 4

            delta = not_after - utc_now
            delta_sec = delta.total_seconds()

            if delta_sec < renewal_before:
                return 5

            return 0
        except:
            return 100

    def print_error(self, msg):
        if self.print_output:
            sys.stderr.write(msg)

    def get_standalone_cmd(self, domain, email=None, expand=False, staging=False, break_certs=False, force=False,
                           webroot=None, **kwargs):
        """
        Returns Certbot standalone command for given settings (domains, staging, email, expand)
        
        :param domain: 
        :param email: 
        :param expand: 
        :param staging: 
        :param break_certs: --break-my-certs when going normal -> staging
        :param force: --force-renewal
        :param webroot:
        :return:
        """
        cmd_email_part = LetsEncrypt.get_email_cmd(email)

        domains = domain if isinstance(domain, list) else [domain]
        domains = ['%s' % util.escape_shell(x.strip()) for x in domains]
        cmd_domains_part = ' -d ' + (' -d '.join(domains))

        cmd_expand_part = '' if not expand else ' --expand '
        cmd_staging = LetsEncrypt.get_staging_cmd(staging)
        cmd_break_certs = '' if not break_certs else ' --break-my-certs '
        cmd_force = '' if not force else ' --force-renewal '
        cmd_method = '--standalone'

        if webroot is not None:
            cmd_method = '--webroot -w %s' % util.escape_shell(webroot)

        cmd = 'certonly %s --text -n --agree-tos %s %s %s %s %s %s' \
              % (cmd_method, cmd_email_part, cmd_expand_part, cmd_staging, cmd_break_certs, cmd_force, cmd_domains_part)

        cmd += self.add_certbot_cmd_config(**kwargs)
        return cmd

    def get_renew_cmd(self, **kwargs):
        cmd = 'renew -n' + self.add_certbot_cmd_config(**kwargs)
        return cmd

    def add_certbot_cmd_config(self, **kwargs):
        cmd = ''
        if 'config_dir' in kwargs:
            cmd += ' --config-dir %s' % util.escape_shell(kwargs.get('config_dir'))
        if 'work_dir' in kwargs:
            cmd += ' --work-dir %s' % util.escape_shell(kwargs.get('work_dir'))
        if 'log_dir' in kwargs:
            cmd += ' --logs-dir %s' % util.escape_shell(kwargs.get('log_dir'))
        return cmd

    @staticmethod
    def get_email_cmd(email):
        email = email if email is not None else ''
        email = email.strip()

        cmd = '--register-unsafely-without-email'
        if len(email) > 0:
            cmd = '--email ' + email
        return cmd

    @staticmethod
    def get_staging_cmd(staging=False):
        if staging:
            return ' --staging '
        else:
            return ' '


