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
import errors
import requests.exceptions as rex


logger = logging.getLogger(__name__)


class CrtShException(errors.Error):
    """General exception"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(CrtShException, self).__init__(message=message, cause=cause)
        self.scan_result = scan_result


class CrtShRequestException(CrtShException):
    """Service request exception"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(CrtShRequestException, self).__init__(message=message, cause=cause, scan_result=scan_result)


class CrtShTimeoutException(CrtShRequestException):
    """Timeout exception"""
    def __init__(self, message=None, cause=None, scan_result=None):
        super(CrtShTimeoutException, self).__init__(message=message, cause=cause, scan_result=scan_result)


#
# Records
#


class CrtShIndexResponse(object):
    """
    Index search result
    """
    def __init__(self, query=None):
        self.query = query
        self.time_start = time.time()
        self.time_end = 0
        self.attempts = 0
        self.success = False
        self.results = []

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


class CrtShDetailResponse(object):
    """
    Certificate detail response
    """
    def __init__(self, crtid=None):
        self.crtid = crtid
        self.time_start = time.time()
        self.time_end = 0
        self.attempts = 0
        self.success = False
        self.result = None

    def __repr__(self):
        return '<CrtShDetailResponse(crtid=%r, success=%r, time_start=%r, time_end=%r, attempts=%r, result=%r)>' \
               % (self.crtid, self.success, self.time_start, self.time_end, self.attempts, self.result)


class CrtShCertDetail(object):
    """
    Certificate detail
    """
    def __init__(self, crtid=None):
        self.crt_id = crtid
        self.sha1 = None
        self.sha256 = None
        self.revocation = []
        self.ct = []

    def __repr__(self):
        return '<CrtShCertDetail(crtid=%r, sha1=%r, sha256=%r, revocation=%r, ct=%r)>' \
               % (self.crt_id, self.sha1, self.sha256, self.revocation, self.ct)


class CrtShCT(object):
    """
    Certificate transparency record
    """
    def __init__(self):
        self.time_stamp = None
        self.entry_id = None
        self.log_operator = None
        self.log_url = None

    def __repr__(self):
        return '<CrtShCT(time_stamp=%r, entry_id=%r, log_operator=%r, log_url=%r)>' \
               % (self.time_stamp, self.entry_id, self.log_operator, self.log_url)


class CrtShRevocation(object):
    """
    Revocation record
    """
    def __init__(self):
        self.mechanism = None
        self.provider = None
        self.status = None
        self.revoked_by = None
        self.revoked_at = None

    def __repr__(self):
        return '<CertShRevocation(mechanism=%r, provider=%r, status=%r, revoked_by=%r, revoked_at=%r)>' \
               % (self.mechanism, self.provider, self.status, self.revoked_by, self.revoked_at)


#
# Processor
#


class CrtProcessor(object):
    """
    crt.sh parser
    """

    BASE_URL = 'https://crt.sh/'

    def __init__(self, timeout=3, attempts=2):
        self.timeout = timeout
        self.attempts = attempts

    def download_crt(self, crt_id, **kwargs):
        """
        Queries download of the raw certificate according to the cert ID
        https://crt.sh/?d=12345
        :param crt_id:
        :param kwargs:
        :return:
        """
        ret = CrtShCertResponse(crtid=crt_id)
        attempts = kwargs.get('attempts', self.attempts)
        timeout = kwargs.get('timeout', self.timeout)
        for attempt in range(attempts):
            try:
                res = requests.get(self.BASE_URL, params={'d': crt_id}, timeout=timeout)
                res.raise_for_status()

                ret.attempts = attempt
                ret.time_end = time.time()
                ret.result = util.strip(res.text)
                ret.success = True
                return ret

            except Exception as e:
                logger.debug('Exception in crt-sh-cert load %s/%s: %s - %s' % (attempt, attempts, crt_id, e))
                logger.debug(traceback.format_exc())
                if attempt + 1 >= attempts:
                    ret.time_end = time.time()
                    if isinstance(e, rex.Timeout):
                        raise CrtShTimeoutException('crtsh service query timeout', cause=e, scan_result=ret)
                    elif isinstance(e, rex.RequestException):  # contains request & response
                        raise CrtShRequestException('crtsh service query exception', cause=e, scan_result=ret)
                    else:
                        raise CrtShException('crtsh query exception', cause=e, scan_result=ret)
                else:
                    time.sleep(1.0)

        return None

    def query(self, query, **kwargs):
        """
        Query domain on crt.sh
        :param query:
        :param kwargs:
        :return:
        """
        ret = CrtShIndexResponse(query=query)
        attempts = kwargs.get('attempts', self.attempts)
        timeout = kwargs.get('timeout', self.timeout)
        for attempt in range(attempts):
            try:
                res = requests.get(self.BASE_URL, params={'q': query}, timeout=timeout)
                res.raise_for_status()
                data = res.text

                ret.attempts = attempt
                ret.time_end = time.time()
                self.parse_index_page(ret, data)

                ret.success = True
                return ret

            except Exception as e:
                logger.debug('Exception in crt-sh-query load %s/%s: %s - %s' % (attempt, attempts, query, e))
                logger.debug(traceback.format_exc())
                if attempt + 1 >= attempts:
                    ret.time_end = time.time()
                    if isinstance(e, rex.Timeout):
                        raise CrtShTimeoutException('crtsh service query timeout', cause=e, scan_result=ret)
                    elif isinstance(e, rex.RequestException):  # contains request & response
                        raise CrtShRequestException('crtsh service query exception', cause=e, scan_result=ret)
                    else:
                        raise CrtShException('crtsh query exception', cause=e, scan_result=ret)
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

    def detail(self, crt_id):
        """
        Certificate detail page load
        :param crt_id: 
        :return: 
        """
        ret = CrtShDetailResponse(crtid=crt_id)
        for attempt in range(self.attempts):
            try:
                res = requests.get(self.BASE_URL, params={'id': crt_id}, timeout=self.timeout)
                res.raise_for_status()
                data = res.text

                ret.attempts = attempt
                ret.time_end = time.time()

                self.parse_detail(ret, data)
                ret.success = True
                return ret

            except Exception as e:
                logger.debug('Exception in crt-sh-detail load %s/%s: %s - %s' % (attempt, self.attempts, crt_id, e))
                logger.debug(traceback.format_exc())
                if attempt + 1 >= self.attempts:
                    raise
                else:
                    time.sleep(1.0)

        return None

    def parse_detail(self, ret, data):
        """
        Parses crt.sh certificate detail page
        :param ret: 
        :param data: 
        :return: 
        """
        tree = html.fromstring(data)
        tables = tree.xpath('//table')
        if len(tables) < 2:
            return ret

        rt = CrtShCertDetail(ret.crtid)
        data_table = tables[1]

        for row in data_table:
            hd = util.lower(util.strip(row[0].text_content()))

            if 'transparency' in hd:
                self.parse_ct(rt, row[1])
            elif 'revocation' in hd:
                self.parse_revocation(rt, row[1])
            elif 'sha-1' in hd:
                rt.sha1 = util.lower(util.strip(row[1].text_content()))
            elif 'sha-256' in hd:
                rt.sha256 = util.lower(util.strip(row[1].text_content()))
            elif 'asn.1' in hd:
                self.parse_text(rt, row[1])

        ret.result = rt
        return ret

    def parse_ct(self, rt, data):
        """
        Parses certificate transparency
        :param rt: 
        :param data: 
        :return: 
        """
        try:
            if len(data) == 0:
                return

            tbl = data[0]
            if tbl.tag != 'table':
                return

            for row in tbl[1:]:
                rc = CrtShCT()

                tstamp = util.strip(row[0].text_content())
                rc.entry_id = util.strip(row[1].text_content())
                rc.log_operator = util.strip(row[2].text_content())
                rc.log_url = util.strip(row[3].text_content())

                if tstamp is not None:
                    rc.time_stamp = tstamp.encode('utf8').replace('\xc2', '').replace('\xa0', '')
                rt.ct.append(rc)

        except Exception as e:
            logger.debug('CT Parsing error: %s', e)

    def parse_revocation(self, rt, data):
        """
        Parses revocation data
        :param rt: 
        :param data: 
        :return: 
        """
        try:
            if len(data) == 0:
                return

            tbl = data[0]
            if tbl.tag != 'table':
                return

            for row in tbl[1:]:
                rc = CrtShRevocation()

                rc.mechanism = util.strip(row[0].text_content())
                rc.provider = util.strip(row[1].text_content())
                rc.status = util.strip(row[2].text_content())
                rc.revoked_by = util.strip(row[3].text_content())
                rc.revoked_at = util.strip(row[4].text_content())

                if rc.revoked_by == 'n/a':
                    rc.revoked_by = None

                if rc.revoked_at == 'n/a':
                    rc.revoked_at = None

                rt.revocation.append(rc)

        except Exception as e:
            logger.debug('Revocation Parsing error: %s', e)

    def parse_text(self, rt, data):
        """
        Parses textual dump
        :param rt: 
        :param data: 
        :return: 
        """
        try:
            # html_simple = (html.tostring(data)).replace('<br>', '\n').replace('&#160;', ' ')
            # html_sub = html.fromstring(html_simple)
            # crt_txt = html_sub.text_content()
            pass

        except Exception as e:
            logger.debug('Text Parsing error: %s', e)

