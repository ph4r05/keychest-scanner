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

