#!/usr/bin/env python
# -*- coding: utf-8 -*-

from past.builtins import basestring    # pip install future
from six.moves.urllib.parse import urlparse, urlencode

import json
import logging
import time
import requests
import util
import datetime
import traceback
import errors
import types
import re
import socket
import random
from trace_logger import Tracelogger
import tldextract
from IPy import IP
from consts import IpType
from cyclic_tools import CyclicTools


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


class TargetUrl(object):
    """
    Represents target address (URL).
    Can return complete URL or its components
    """
    def __init__(self, url=None, scheme=None, host=None, port=None, target_url=None):
        """
        Assembles URL from the components. Either URL or parts
        :param url:
        :param scheme:
        :param host:
        :param port:
        :param target_url:
        :type target_url: TargetUrl
        """
        self.scheme = scheme
        self.host = host
        self.port = port

        if url is not None:
            self.scheme, self.host, self.port = TlsDomainTools.parse_scheme_host_port(url)

        if target_url is not None:
            self.scheme = target_url.scheme
            self.host = target_url.host
            self.port = target_url.port

        self.scheme, self.port = TlsDomainTools.scheme_port_detect(self.scheme, self.port)

    def __repr__(self):
        return '<TargetUrl(scheme=%r, host=%r, port=%r)>' % (self.scheme, self.host, self.port)

    def __str__(self):
        return self.url()

    def components(self):
        """
        Returns tuple (scheme, host, port)
        :return:
        """
        return self.scheme, self.host, self.port

    def url(self):
        """
        Returns URL form
        :return:
        """
        return TlsDomainTools.assemble_url(self.scheme, self.host, self.port)


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
    def parse_hostname(url):
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
    def parse_hostname_port(url):
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
    def parse_fqdn(url):
        """
        Parses FQDN from the url, removes wildcards
        :param url:
        :return:
        """
        hostname = TlsDomainTools.parse_hostname(url)
        return TlsDomainTools.fqdn(hostname)

    @staticmethod
    def fqdn(hostname):
        """
        Removes all wildcards from the hostname
        :param hostname:
        :return:
        """
        components = hostname.split('.')
        ret = []
        for comp in reversed(components):
            if '*' in comp or '%' in comp:
                break
            ret.append(comp)

        return '.'.join(reversed(ret))

    @staticmethod
    def has_wildcard(hostname):
        """
        Returns true if domain has wildcard
        :param hostname:
        :return:
        """
        return '*.' in hostname or '%' in hostname

    @staticmethod
    def split_scheme(url):
        """
        Splits url to the scheme and the rest. Scheme may be null.
        :param url:
        :type url: str
        :return:
        """
        if util.is_empty(url):
            return url

        parts = url.split('://', 1)
        return parts if len(parts) == 2 else [None, url]

    @staticmethod
    def parse_host(url):
        """
        Removes path components from the URL, strips also scheme if present.
        Returns only host (with port optionally).
        :param url:
        :type url: str
        :return:
        """
        if util.is_empty(url):
            return url

        scheme, host = TlsDomainTools.split_scheme(url)

        pos = host.find('/')
        return host if pos == -1 else host[:pos]

    @staticmethod
    def parse_scheme_host_port(url):
        """
        Parses URL to the scheme, host, port
        :return:
        """
        p = TlsDomainTools.url_parse(url)
        if p.scheme is not None and p.netloc is not None:
            scheme, port = TlsDomainTools.scheme_port_detect(p.scheme, p.port)
            return scheme, p.hostname, port

        scheme, rest = TlsDomainTools.split_scheme(url)
        hostname, port = TlsDomainTools.parse_hostname_port(rest)
        scheme, port = TlsDomainTools.scheme_port_detect(scheme, port)
        return scheme, hostname, port

    @staticmethod
    def normalize_url(url):
        """
        Normalizes url, removes path.
        Adds default scheme, default port. (https, 443)
        :param url:
        :return:
        """
        scheme, hostname, port = TlsDomainTools.parse_scheme_host_port(url)
        return TlsDomainTools.assemble_url(scheme, hostname, port)

    @staticmethod
    def assemble_url(scheme='https', hostname='127.0.0.1', port=443):
        """
        Assembles full URL, even if scheme and port are set to None, default vals are used.
        :param scheme:
        :param hostname:
        :param port:
        :return:
        """
        if scheme is None:
            scheme = 'https'
        if port is None:
            port = 443
        scheme, port = TlsDomainTools.scheme_port_detect(scheme, port)
        return '%s://%s:%s' % (scheme, hostname, port)

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

    @staticmethod
    def scheme_port_detect(scheme, port):
        """
        Scheme / port detection from one another, https by default.
        :param scheme:
        :param port:
        :return:
        """
        if port is None:
            if scheme == 'https':
                port = 443
            elif scheme == 'http':
                port = 80
        port = int(util.defval(port, 443))

        if port == 80 and scheme is None:
            scheme = 'http'
        else:
            scheme = util.defval(scheme, 'https')

        return scheme, port

    @staticmethod
    def get_ip_type(hostname):
        """
        Returns 0 if the host is not IP, 1 for IPv4, 2 for IPv6
        :param hostname:
        :return:
        """
        if TlsDomainTools.is_valid_ipv4_address(hostname):
            return IpType.IPv4
        if TlsDomainTools.is_valid_ipv6_address(hostname):
            return IpType.IPv6
        return IpType.NOT_IP

    @staticmethod
    def get_ip_family(ip=None, type_idx=None):
        """
        Returns 0 if the host is not IP, 1 for IPv4, 2 for IPv6
        :param hostname:
        :return:
        """
        if ip is not None:
            type_idx = TlsDomainTools.get_ip_type(ip)
        if type_idx == IpType.IPv4:
            return IpType.NET_IPv4
        if type_idx == IpType.IPv6:
            return IpType.NET_IPv6
        return IpType.NOT_IP

    @staticmethod
    def is_ip(hostname):
        """
        Returns true if the hostname is IPv4 or IPv6
        :param hostname:
        :return:
        """
        ipv4 = TlsDomainTools.is_valid_ipv4_address(hostname)
        if ipv4:
            return True
        return TlsDomainTools.is_valid_ipv6_address(hostname)

    @staticmethod
    def is_valid_ipv4_address(hostname):
        """
        Returns true if the hostname is IPv4
        :param hostname:
        :return:
        """
        r = r'^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
        if re.match(r, hostname):
            return True
        return False

    @staticmethod
    def is_valid_ipv6_address(address):
        """
        Simple IPV6 address validation using hacky socket.inet_pton
        :param address:
        :return:
        """
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        return True

    @staticmethod
    def get_top_domain(hostname):
        """
        Extracts the top domain from the hostname - removes subdomains.
        Naive implementation
        :param hostname:
        :return:
        """
        return tldextract.extract(hostname).registered_domain

    @staticmethod
    def can_connect(hostname):
        """
        Return true if direct connection can be made (either valid IP address or domain name)
        :param hostname:
        :return:
        """
        if TlsDomainTools.is_ip(hostname):
            return True

        if '.' not in hostname:
            return False

        if not re.match(r'^[a-zA-Z0-9._-]+$', hostname):
            return False

        return True

    @staticmethod
    def can_whois(hostname):
        """
        Returns true if whois can be called on the hostname
        :param hostname:
        :return:
        """
        if TlsDomainTools.is_ip(hostname):
            return False

        if '.' not in hostname:
            return False

        if not re.match(r'^[a-zA-Z0-9._-]+$', hostname):
            return False

        return True

    @staticmethod
    def urlize(url):
        """
        Returns url object from the given object.
        :param url:
        :return:
        """
        if isinstance(url, TargetUrl):
            return url
        elif util.is_string(url):
            return TargetUrl(url=url)
        elif isinstance(url, tuple) and len(url) == 3:
            return TargetUrl(scheme=url[0], host=url[1], port=url[2])
        elif url is None:
            return url
        elif util.is_number(url) or isinstance(url, bool):
            raise ValueError('Unsupported input - numbers')
        else:
            return TargetUrl(url=str(url))

    @staticmethod
    def strip_query(url):
        """
        Strips the query part, if present, from the url string
        :param url:
        :return:
        """
        if url is None:
            return None
        pos = url.find('?')
        return url if pos == -1 else url[:pos]

    @staticmethod
    def is_ip_private(ip):
        """
        Tries to determine if IP is private
        :param ip:
        :return:
        """
        try:
            ip = IP(ip)
            tp = util.lower(ip.iptype())
            return tp != 'public' and not tp.startswith('allocated')
        except:
            pass
        return False

    @staticmethod
    def ip_to_int(ip):
        """
        Converts IPv4 to integer.
        123.123.123.123 -> int

        :param ip:
        :return:
        """
        octets = str(ip).split('.')
        if len(octets) != 4:
            raise ValueError('Invalid IPv4 format, 4 octets required')

        res = 0
        for idx, octet in enumerate([int(x) for x in reversed(octets)]):
            res |= octet << (8*idx)

        return res

    @staticmethod
    def int_to_ip(n):
        """
        Converts 32bit integer to the IP
        :param n:
        :return:
        """
        ip = [str((n >> (8*i)) & 0xff) for i in range(0, 4)]
        return '.'.join(reversed(ip))

    @staticmethod
    def ip_range(ip_beg, ip_end):
        """
        Returns size of the IP address range given by two IP addresses
        :param ip_beg:
        :param ip_end:
        :return:
        """
        return 1 + TlsDomainTools.ip_to_int(ip_end) - TlsDomainTools.ip_to_int(ip_beg)

    @staticmethod
    def iter_ips(ip_start=None, ip_stop=None, ip_start_int=None, ip_stop_int=None):
        """
        Iterates over the IP range in the random order - not to trigger IDS while scanning.
        :param ip_start:
        :param ip_stop:
        :param ip_start_int:
        :param ip_stop_int:
        :return:
        """
        if ip_start_int is None:
            ip_start_int = TlsDomainTools.ip_to_int(ip_start)

        if ip_stop_int is None:
            ip_stop_int = TlsDomainTools.ip_to_int(ip_stop)

        if ip_stop_int < ip_start_int:
            raise ValueError('Invalid IP order, end > start')

        # Simple case - small range, generate sequence and shuffle
        if (ip_stop_int - ip_start_int) < 250:
            lst = range(ip_start_int, ip_stop_int + 1)
            random.shuffle(lst)
            for cur in lst:
                yield TlsDomainTools.int_to_ip(cur)
            return

        # General case - large range, generate random cyclic group of similar size and generate elements
        # in random order.
        ctool = CyclicTools(1 + ip_stop_int - ip_start_int)
        ctool.init(random_offset=True)

        for cur in ctool.iter():
            yield TlsDomainTools.int_to_ip(ip_start_int + cur)

