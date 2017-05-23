#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import time
import requests
from lxml import html
import util
import datetime
import traceback


logger = logging.getLogger(__name__)


class CrtShIndexResponse(object):
    """
    Index search result
    """
    def __init__(self, query=None, results=None):
        self.query = query
        self.time_start = time.time()
        self.time_end = 0
        self.attempts = 0
        self.success = False
        self.results = results

    def add(self, x):
        if self.results is None:
            self.results = []
        self.results.append(x)

    def __repr__(self):
        return '<CrtShIndexResponse(query=%r, success=%r, time_start=%r, time_end=%r, attempts=%r, results=%r)>' \
               % (self.query, self.success, self.time_start, self.time_end, self.attempts, self.results)


class CrtShIndexRecord(object):
    """
    One single record from the index search
    """
    def __init__(self, crtid=None, logged_at=None, not_before=None, identity=None, ca_dn=None, ca_id=None):
        self.id = crtid
        self.logged_at = logged_at
        self.not_before = not_before
        self.identity = identity
        self.ca_dn = ca_dn
        self.ca_id = ca_id

    def __repr__(self):
        return '<CrtShIndexRecord>(crtid=%r, logged_at=%r, not_before=%r, identity=%r, ca_dn=%r, ca_id=%r)' \
               % (self.id, self.logged_at, self.not_before, self.identity, self.ca_dn, self.ca_id)


class CrtShCertResponse(object):
    """
    Wrapping response for the certificate download
    """
    def __init__(self, crtid=None):
        self.crtid = crtid
        self.time_start = time.time()
        self.time_end = 0
        self.attempts = 0
        self.success = False
        self.result = None

    def __repr__(self):
        return '<CrtShCertResponse(crtid=%r, success=%r, time_start=%r, time_end=%r, attempts=%r, result=%r)>' \
               % (self.crtid, self.success, self.time_start, self.time_end, self.attempts, self.result)


class CrtProcessor(object):
    """
    crt.sh parser
    """

    BASE_URL = 'https://crt.sh/'

    def __init__(self):
        self.timeout = 10
        self.attempts = 3

    def download_crt(self, crt_id):
        """
        Queries download of the raw certificate according to the cert ID
        https://crt.sh/?d=12345
        :param crt_id: 
        :return: 
        """
        ret = CrtShCertResponse(crtid=crt_id)
        for attempt in range(self.attempts):
            try:
                res = requests.get(self.BASE_URL, params={'d': crt_id}, timeout=10)
                res.raise_for_status()

                ret.attempts = attempt
                ret.time_end = time.time()
                ret.result = res.text
                ret.success = True
                return ret

            except Exception as e:
                logger.debug('Exception in crt-sh load: %s' % e)
                logger.debug(traceback.format_exc())
                if attempt >= self.attempts:
                    raise
                else:
                    time.sleep(1.0)

        return None

    def query(self, domain):
        """
        Query domain on crt.sh
        :param domain: 
        :return: 
        """
        ret = CrtShIndexResponse(query=domain)
        for attempt in range(self.attempts):
            try:
                res = requests.get(self.BASE_URL, params={'q': domain}, timeout=10)
                res.raise_for_status()
                data = res.text

                ret.attempts = attempt
                ret.time_end = time.time()
                self.parse_index_page(ret, data)

                ret.success = True
                return ret

            except Exception as e:
                logger.debug('Exception in crt-sh load: %s' % e)
                logger.debug(traceback.format_exc())
                if attempt >= self.attempts:
                    raise
                else:
                    time.sleep(1.0)

        return None

    def parse_index_page(self, ret, data):
        """
        Parses index page
        :param query: 
        :param data: 
        :return: 
        """
        tree = html.fromstring(data)
        res_table = tree.xpath('//table//table')
        if util.is_empty(res_table):
            return ret

        res_table = res_table[0]
        if len(res_table) <= 1:
            return ret

        rows = res_table[1:]
        for row in rows:
            col_cnt = len(row)

            cur_res = CrtShIndexRecord()
            cur_res.id = util.strip(row[0].text_content())

            cur_res.logged_at = util.unix_time(datetime.datetime.strptime(
                util.strip(row[1].text_content()), '%Y-%m-%d'))
            cur_res.not_before = util.unix_time(datetime.datetime.strptime(
                util.strip(row[2].text_content()), '%Y-%m-%d'))

            ca_offset = 0
            if col_cnt >= 5:
                cur_res.identity = util.strip(row[3].text_content())
                ca_offset += 1

            cur_res.ca_dn = util.strip(row[3 + ca_offset].text_content())
            try:
                ca_href = util.strip(row[3 + ca_offset][0].attrib['href'])
                if not util.is_empty(ca_href):
                    cur_res.ca_id = int(ca_href.rsplit('=', 1)[1])
            except:
                pass

            ret.add(cur_res)

        return ret

