#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Database manager
"""

from past.builtins import basestring  # pip install future
from past.builtins import cmp
from future.utils import iteritems

import logging
import time

import sqlalchemy as salch

from .errors import Error
from .dbutil import DbDomainName, DbBaseDomain, DbCrtShQueryInput, DbWatchTarget, DbSubdomainWatchResultEntry, DbHelper, \
    DbWatchAssoc, DbIpAddress, DbTlsScanDesc, DbTlsScanParams, DbTlsScanDescExt, DbWatchService, ModelUpdater
from .tls_domain_tools import TlsDomainTools
from .trace_logger import Tracelogger
from . import dbutil, util, util_cert

logger = logging.getLogger(__name__)


class DatabaseManager(object):
    """
    Base DB manager for certificate related tasks
    """

    def __init__(self):
        self.db = None
        self.config = None
        self.trace_logger = Tracelogger(logger)

    def init(self, **kwargs):
        """
        Initializes the Db manager
        :param kwargs:
        :return:
        """
        if 'db' in kwargs:
            self.db = kwargs.get('db')
        if 'config' in kwargs:
            self.config = kwargs.get('config')
        if 'trace_logger' in kwargs:
            self.trace_logger = kwargs.get('trace_logger')

    #
    # Generic loads
    #

    def load_domain_name(self, s, domain_name, fetch_first=True, pre_commit=True):
        """
        Arbitrary domain name
        :param s:
        :param domain_name:
        :param fetch_first:
        :param pre_commit:
        :return:
        """
        obj = DbDomainName()
        obj.domain_name = domain_name

        def pre_add(obj):
            if obj.top_domain_id is not None:
                return

            # top domain load
            top_domain_obj, is_new = self.try_load_top_domain(s, TlsDomainTools.parse_fqdn(domain_name))
            if top_domain_obj is not None:
                obj.top_domain_id = top_domain_obj.id

        ret = dbutil.ModelUpdater.load_or_insert(s, obj=obj, select_cols=[DbDomainName.domain_name],
                            pre_add_fnc=pre_add,
                            pre_commit=pre_commit,
                            fetch_first=fetch_first,
                            fail_sleep=0.01,
                            trace_logger=self.trace_logger,
                            log_message='domain name fetch/save error: %s' % domain_name)
        return ret

    def try_load_top_domain(self, s, domain):
        """
        Determines top domain & loads / inserts it to the DB
        :param s:
        :param domain:
        :return:
        :rtype: tuple[DbBaseDomain, is_new]
        """
        try:
            if util.is_empty(domain):
                return None, None

            top_domain = TlsDomainTools.get_top_domain(domain)
            if util.is_empty(top_domain):
                return None, None

            top_domain, is_new = self.load_top_domain(s, top_domain)
            return top_domain, is_new

        except:
            return None, None

    def load_top_domain(self, s, top_domain, attempts=5):
        """
        Loads or creates a new top domain record.
        :param s:
        :param top_domain:
        :return:
        :rtype Tuple[DbBaseDomain, is_new]
        """
        obj = DbBaseDomain()
        obj.domain_name = top_domain

        ret = dbutil.ModelUpdater.\
            load_or_insert(s, obj=obj, select_cols=[DbBaseDomain.domain_name],
                            pre_commit=True, fetch_first=True, fail_sleep=0.01,
                            trace_logger=self.trace_logger, log_message='top domain fetch/save error')
        return ret

    def get_crtsh_input(self, s, query, query_type=None):
        """
        CRTSH loads input
        :param s:
        :param query:
        :param query_type:
        :return: Tuple[DbCrtShQueryInput, Boolean]
        """
        if isinstance(query, DbCrtShQueryInput):
            return query, 0

        query_input = None
        if isinstance(query, tuple):
            query_input, query_type = query[0], query[1]

        else:
            query_input = query
        if query_type is None:
            query_type = 0

        return self.load_crtsh_input(s, query_input, query_type)

    def load_crtsh_input(self, s, domain, query_type=0, attempts=5, **kwargs):
        """
        Loads CRTSH query type from DB or creates a new record
        :param s:
        :param domain:
        :param query_type:
        :param attempts:
        :return
        :rtype tuple[DbCrtShQueryInput, bool]
        """
        obj = DbCrtShQueryInput()
        obj.iquery = domain
        obj.itype = query_type
        obj.created_at = salch.func.now()

        def pre_add(obj):
            if obj.sld_id is not None:
                return

            # top domain load
            top_domain_obj, is_new = self.try_load_top_domain(s, TlsDomainTools.parse_fqdn(domain))
            if top_domain_obj is not None:
                obj.sld_id = top_domain_obj.id

        ret = dbutil.ModelUpdater \
            .load_or_insert(s=s, obj=obj, select_cols=[DbCrtShQueryInput.iquery, DbCrtShQueryInput.itype],
                            pre_add_fnc=pre_add,
                            pre_commit=True,
                            fetch_first=True,
                            fail_sleep=0.01,
                            trace_logger=self.trace_logger,
                            log_message='crtsh input fetch/save error: %s' % domain)
        return ret

    def load_default_watch_target(self, s, host, attempts=5):
        """
        Tries to load default watch target (https, 443) or creates a new if does not found
        :param s:
        :param host:
        :param attempts:
        :return:
        """
        for attempt in range(attempts):
            try:
                ret = s.query(DbWatchTarget)\
                    .filter(DbWatchTarget.scan_host == host)\
                    .filter(DbWatchTarget.scan_port == '443')\
                    .filter(DbWatchTarget.scan_scheme == 'https')\
                    .first()
                if ret is not None:
                    return ret, 0

            except Exception as e:
                logger.error('Error fetching DbWatchTarget from DB: %s : %s' % (host, e))
                self.trace_logger.log(e, custom_msg='DbWatchTarget fetch error')

            # insert attempt now
            try:
                ret = DbWatchTarget()
                ret.scan_scheme = 'https'
                ret.scan_port = '443'
                ret.scan_host = host
                ret.created_at = salch.func.now()
                ret.updated_at = salch.func.now()

                # top domain
                top_domain_obj, is_new = self.try_load_top_domain(s, TlsDomainTools.parse_fqdn(host))
                if top_domain_obj is not None:
                    ret.top_domain_id = top_domain_obj.id

                s.add(ret)
                s.flush()
                return ret, 1

            except Exception as e:
                s.rollback()
                logger.error('Error inserting DbWatchTarget to DB: %s : %s' % (host, e))
                self.trace_logger.log(e, custom_msg='DbWatchTarget fetch error')

            time.sleep(0.01)
        raise Error('Could not store / load DbWatchTarget')

    def load_subdomains(self, s, watch_id, subs):
        """
        Tries to load all subdomains with given domain name
        :param s:
        :param watch_id:
        :param subs:
        :return:
        """
        was_array = True
        if subs is not None and not isinstance(subs, list):
            subs = [subs]
            was_array = False

        q = s.query(DbSubdomainWatchResultEntry)

        if watch_id is not None:
            q = q.filter(DbSubdomainWatchResultEntry.watch_id == watch_id)

        if subs is not None:
            q = q.filter(DbSubdomainWatchResultEntry.name.in_(list(subs)))

        ret = {}
        res = q.all()
        for cur in res:
            if not was_array:
                return cur

            ret[cur.name] = cur

        return ret if was_array else None

    def load_num_active_hosts(self, s, owner_id):
        """
        Loads number of active user hosts
        :param s:
        :param owner_id:
        :return:
        """
        return DbHelper.get_count(
            s.query(DbWatchAssoc)\
            .filter(DbWatchAssoc.owner_id == owner_id)\
            .filter(DbWatchAssoc.deleted_at == None)\
            .filter(DbWatchAssoc.disabled_at == None))

    def update_last_dns_scan_id(self, s, db_dns):
        """
        Update cached last dns scan id in the watch_target.
        Optimistic locking on the last_dns_scan_id - updates only with newer values (sequentially higher)
        :param s:
        :param db_dns:
        :return:
        """
        stmt = salch.update(DbWatchTarget) \
            .where(DbWatchTarget.id == db_dns.watch_id) \
            .where(salch.or_(
                DbWatchTarget.last_dns_scan_id == None,
                DbWatchTarget.last_dns_scan_id < db_dns.id)
        ).values(last_dns_scan_id=db_dns.id)
        s.execute(stmt)

    def update_watch_last_scan_at(self, s, watch_id):
        """
        Updates last scan for the watch to now
        :param s:
        :param watch_id:
        :return:
        """
        stmt = salch.update(DbWatchTarget) \
            .where(DbWatchTarget.id == watch_id) \
            .values(last_scan_at=salch.func.now())
        s.execute(stmt)

    def update_watch_ip_type(self, s, target, domain=None):
        """
        Fixes IP type for new watches
        :param s:
        :param target:
        :type target: DbWatchTarget
        :param domain:
        :return:
        """
        if target is not None:
            ip_type = TlsDomainTools.get_ip_type(target.scan_host)
            if ip_type == target.is_ip_host:
                return

            target.is_ip_host = ip_type
            stmt = salch.update(DbWatchTarget) \
                .where(DbWatchTarget.id == target.id) \
                .values(is_ip_host=target.is_ip_host)
            s.execute(stmt)

    def load_ip_address(self, s, ip):
        """
        IP address load/save
        :param s:
        :param ip:
        :return:
        """
        obj = DbIpAddress()
        obj.ip_addr = ip

        def pre_add(obj):
            if obj.ip_type is not None:
                return
            obj.ip_type = TlsDomainTools.get_ip_family(ip)

        ret = dbutil.ModelUpdater \
            .load_or_insert(s, obj=obj, select_cols=[DbIpAddress.ip_addr],
                            pre_add_fnc=pre_add,
                            pre_commit=True,
                            fetch_first=True,
                            fail_sleep=0.01,
                            trace_logger=self.trace_logger,
                            log_message='IP fetch/save error: %s' % ip)
        return ret

    def load_tls_desc(self, s, ip_id, svc_id, port=443):
        """
        TLS descriptor
        :param s:
        :param ip_id:
        :param svc_id:
        :param port:
        :return:
        """
        obj = DbTlsScanDesc()
        obj.ip_id = ip_id
        obj.sni_id = svc_id
        obj.port = port

        ret = dbutil.ModelUpdater \
            .load_or_insert(s, obj=obj,
                            select_cols=[DbTlsScanDesc.ip_id, DbTlsScanDesc.sni_id, DbTlsScanDesc.scan_port],
                            pre_commit=True,
                            fetch_first=True,
                            fail_sleep=0.01,
                            trace_logger=self.trace_logger,
                            log_message='TLS desc fetch/save error: %s:%s %s' % (ip_id, svc_id, port))
        return ret

    def load_tls_params(self, s, tls_ver=1, key_type=1, ciphers=None):
        """
        TLS scan parameters
        :param s:
        :param tls_ver:
        :param key_type:
        :param ciphers:
        :return:
        """
        obj = DbTlsScanParams()
        obj.tls_ver = tls_ver
        obj.key_type = key_type
        obj.cipersuite_set = ciphers

        ret = dbutil.ModelUpdater \
            .load_or_insert(s, obj=obj,
                            select_cols=[DbTlsScanParams.tls_ver, DbTlsScanParams.key_type, DbTlsScanParams.cipersuite_set],
                            pre_commit=True,
                            fetch_first=True,
                            fail_sleep=0.01,
                            trace_logger=self.trace_logger,
                            log_message='TLS param fetch/save error: %s %s %s' % (tls_ver, key_type, ciphers))
        return ret

    def load_tls_desc_ex(self, s, desc_id, param_id):
        """
        Desc & param load
        :param s:
        :param desc_id:
        :param param_id:
        :return:
        """
        obj = DbTlsScanDescExt()
        obj.tls_desc_id = desc_id
        obj.tls_params_id = param_id

        ret = dbutil.ModelUpdater \
            .load_or_insert(s, obj=obj,
                            select_cols=[DbTlsScanDescExt.tls_desc_id, DbTlsScanDescExt.tls_params_id],
                            pre_commit=True,
                            fetch_first=True,
                            fail_sleep=0.01,
                            trace_logger=self.trace_logger,
                            log_message='TLS desc ext fetch/save error: %s %s' % (desc_id, param_id))
        return ret

    def load_watch_service(self, s, svc_name):
        """
        Creates a new service record if does not exist or load existing one
        :param s:
        :param svc_name:
        :return:
        :rtype: tuple[DbWatchService, bool]
        """
        svc = DbWatchService()
        svc.service_name = svc_name
        db_svc, is_new = ModelUpdater.load_or_insert(s, svc, [DbWatchService.service_name])
        if not is_new:
            return db_svc, is_new

        # Augment with dates, top domain & crtsh input fields
        db_svc.created_at = salch.func.now()
        db_svc.updated_at = salch.func.now()

        # top domain
        top_domain_obj, is_new = self.try_load_top_domain(s, TlsDomainTools.parse_fqdn(svc_name))
        if top_domain_obj is not None:
            db_svc.top_domain_id = top_domain_obj.id

        # crtsh input
        db_input, inp_is_new = self.get_crtsh_input(s, svc_name)
        if db_input is not None:
            db_svc.crtsh_input_id = db_input.id

        s.merge(db_svc)
        return db_svc, is_new


