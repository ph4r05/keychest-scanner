#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import time
import requests
import util
import datetime
import traceback
import errors
import types
from trace_logger import Tracelogger
from six.moves.urllib.parse import urlparse, urlencode


logger = logging.getLogger(__name__)


class HstsInfo(object):
    def __init__(self):
        self.enabled = False
        self.max_age = None
        self.include_subdomains = False
        self.preload = False


class PinningInfo(object):
    def __init__(self):
        self.enabled = False
        self.report_only = False
        self.pins = []
        self.max_age = None
        self.include_subdomains = False
        self.report_uri = None


class TlsDomainTools(object):
    """
    Domain tools
    """
    def __init__(self):
        pass

    @staticmethod
    def url_parse(url):
        """
        Returns url parse result
        :param url: 
        :return: 
        """
        return urlparse(url)

    @staticmethod
    def base_domain(url):
        """
        Returns base domain from the url
        :param url: 
        :return: 
        """
        p = TlsDomainTools.url_parse(url)
        if util.is_empty(p.scheme) and util.is_empty(p.hostname):
            p = TlsDomainTools.url_parse('https://%s' % url)

        return p.hostname

    @staticmethod
    def base_domain_port(url):
        """
        Returns base domain from the url
        :param url: 
        :return: domain, port
        """
        p = TlsDomainTools.url_parse(url)
        if util.is_empty(p.scheme) and util.is_empty(p.hostname):
            p = TlsDomainTools.url_parse('https://%s' % url)

        return p.hostname, p.port

    @staticmethod
    def gen_domain_wildcards(domain):
        """
        Returns list of possible wildcard domains matching the given one.
        test.alpha.dev.domain.com ->
            - *.alpha.dev.domain.com
            - *.dev.domain.com
            - *.domain.com
        :param domain: 
        :return: 
        """
        ret = []
        components = domain.split('.')
        cln = len(components)
        for i in range(1, cln - 1):
            ret.append('*.%s' % ('.'.join(components[i:])))

        return ret

    @staticmethod
    def match_domain(domain, alt_names):
        """
        Verifies if given domain matches at least one alt_name in alt names.
         Returns list of all matched alt names.
        :param domain: string domain, no wildcard is allowed, fqdn.
        :param alt_names: iterable of alt names (strings)
        :return: list of matching domains
        """
        domains = [domain] + TlsDomainTools.gen_domain_wildcards(domain)

        alt_names_set = set(list(alt_names))
        domains_set = set(domains)

        return list(domains_set & alt_names_set)

    @staticmethod
    def follow_domain_redirect(url, **kwargs):
        """
        Performs basic HTTP request on the url, returns redirect domain
        :param url: 
        :return: 
        """
        r = requests.get(url, **kwargs)
        return r.url

    @staticmethod
    def get_alt_names(certificates, include_cn=True):
        """
        Dumps all alt names from the certificates
        :param certificates:
        :param include_cn:
        :return:
        """
        if not isinstance(certificates, types.ListType):
            certificates = [certificates]

        alt_names = []
        for crt in certificates:
            arr = [util.utf8ize(x) for x in util.try_get_san(crt)]
            if include_cn:
                cname = util.utf8ize(util.try_get_cname(crt))
                if not util.is_empty(cname):
                    arr.append(cname)
            alt_names.extend(arr)

        return util.stable_uniq(alt_names)

    @staticmethod
    def detect_hsts(res):
        """
        Detects HSTS from the requests response
        :param req:
        :return:
        """
        ret = HstsInfo()
        hdr = res.headers
        sts = util.defvalkey_ic(hdr, 'Strict-Transport-Security')
        if sts is None:
            return ret

        ret.enabled = True
        parts = sts.split(';')
        parts = util.strip(parts)
        parts = util.lower(parts)
        for part in parts:
            try:
                if part.startswith('max-age'):
                    ret.max_age = int(part.split('=')[1])
                elif part == 'preload':
                    ret.preload = True
                elif part.startswith('includesub'):
                    ret.include_subdomains = True

            except Exception as e:
                logger.debug('Exception in parsing HSTS: %s' % e)

        return ret

    @staticmethod
    def detect_pinning(res):
        """
        Detects certificate pinning in the requests response
        :param res:
        :return:
        """
        ret = PinningInfo()
        hdr = res.headers

        report_only = True
        png = util.defvalkey_ic(hdr, 'Public-Key-Pins')
        if png is not None:
            report_only = False
        else:
            png = util.defvalkey_ic(hdr, 'Public-Key-Pins-Report-Only')

        if png is None:
            return ret

        ret.enabled = True
        ret.report_only = report_only
        parts = png.split(';')
        parts = util.strip(parts)

        for part in parts:
            try:
                sub_part = part.split('=', 1)
                part_name = util.lower(sub_part[0])
                if part_name == 'pin-sha256':
                    ret.pins.append(util.stip_quotes(sub_part[1]))
                elif part_name == 'max-age':
                    ret.max_age = int(sub_part[1])
                elif part_name == 'includesubdomains':
                    ret.include_subdomains = True
                elif part_name == 'report-uri':  # bug here if uri contains ';'
                    ret.report_uri = util.stip_quotes(sub_part[1])

            except Exception as e:
                logger.debug('Exception in parsing HSTS: %s' % e)

        return ret

