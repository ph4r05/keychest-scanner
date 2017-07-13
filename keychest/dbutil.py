#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import util
import errors
import logging
import copy
import collections

from sqlalchemy import create_engine, UniqueConstraint, ColumnDefault
from sqlalchemy import exc as sa_exc
from sqlalchemy import case, literal_column, orm
from sqlalchemy.sql import expression
from sqlalchemy.ext.compiler import compiles
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, query
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import INTEGER
import sqlalchemy as sa
from warnings import filterwarnings
import MySQLdb as MySQLDatabase
from consts import DbScanType


"""
Basic database utils.
"""

logger = logging.getLogger(__name__)

# Base for schema definitions
Base = declarative_base()


class AlembicDataMigration(Base):
    """
    Alembic data migration
    """
    __tablename__ = 'alembic_version_data'
    id = Column(BigInteger, primary_key=True)
    schema_ver = Column(BigInteger)
    data_ver = Column(BigInteger)


class ScanJob(Base):
    """
    Github repositories for the user
    """
    __tablename__ = 'scan_jobs'
    id = Column(BigInteger, primary_key=True)
    uuid = Column(String(36), nullable=False, unique=True)

    scan_host = Column(String(255), nullable=True)
    scan_scheme = Column(String(255), nullable=True)
    scan_port = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())

    state = Column(String(255), nullable=True)
    progress = Column(String(255), nullable=True)

    user_id = Column(BigInteger, nullable=True)
    user_ip = Column(String(255), nullable=True)
    user_sess = Column(String(255), nullable=True)
    whois_check_id = Column(ForeignKey('whois_result.id', name='sjob_whois_result_id', ondelete='SET NULL'),
                            nullable=True, index=True)  # whois check ID
    crtsh_check_id = Column(ForeignKey('crtsh_query.id', name='sjob_crtsh_query_id', ondelete='SET NULL'),
                            nullable=True, index=True)  # crtsh check ID
    dns_check_id = Column(ForeignKey('scan_dns.id', name='sjob_scan_dns_id', ondelete='SET NULL'),
                          nullable=True, index=True)  # dns check ID
    crtsh_checks = Column(String(255), nullable=True)  # json of crtsh checks


class Certificate(Base):
    """
    Certificate object
    """
    __tablename__ = 'certificates'
    __table_args__ = (UniqueConstraint('fprint_sha1', name='crt_fprint_sha1_uniqe'),)

    id = Column(BigInteger, primary_key=True)
    crt_sh_id = Column(BigInteger, index=True, nullable=True)
    crt_sh_ca_id = Column(BigInteger, nullable=True)

    fprint_sha1 = Column(String(40), index=True, nullable=False)
    fprint_sha256 = Column(String(64), index=True, nullable=True)

    valid_from = Column(DateTime, default=None, nullable=True)
    valid_to = Column(DateTime, default=None, nullable=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())

    cname = Column(Text, nullable=True)
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True)
    is_ca = Column(SmallInteger, nullable=False, default=0)
    is_self_signed = Column(SmallInteger, nullable=False, default=0)
    is_precert = Column(SmallInteger, nullable=False, default=0)
    is_precert_ca = Column(SmallInteger, nullable=False, default=0)
    parent_id = Column(BigInteger, nullable=True)  # when found in cert chain
    is_le = Column(SmallInteger, nullable=False, default=0)
    is_cloudflare = Column(SmallInteger, nullable=False, default=0)

    key_type = Column(SmallInteger, nullable=True)  # 1=rsa, 2=dsa, 3=ecc, 4=unknown
    key_bit_size = Column(Integer, nullable=True)  # bitsize of the public part, depends on the type, mainly for RSA & ECC
    sig_alg = Column(Integer, nullable=True)  # signature hash used, SHA1, SHA2, ...

    alt_names = Column(Text, nullable=True)  # json encoded alt names array. denormalized for efficiency

    source = Column(String(255), nullable=True)  # CT / crt.sh / manual

    pem = Column(Text, nullable=True)

    def __init__(self):
        self.alt_names_arr = []

    @orm.reconstructor
    def init_on_load(self):
        self.alt_names_arr = util.defval(util.try_load_json(self.alt_names), [])

    @property
    def all_names(self):
        return list(self.alt_names_arr) + ([self.cname] if self.cname else [])


class CertificateAltName(Base):
    """
    Certificate alt names, simple association table to certificate for DB based search.
    Normalized version of alt names, used only for SQL searches, the certificate table holds alt names also
    in JSON (denormalized copy) to avoid joins in normal operation.
    """
    __tablename__ = 'certificate_alt_names'
    cert_id = Column(ForeignKey('certificates.id', name='cert_alt_name_cert_id', ondelete='CASCADE'),
                     nullable=False, index=True)  # certificate ID foreign key
    alt_name = Column(String(255), index=True, primary_key=True, nullable=False)


class DbSubdomainScanBlacklist(Base):
    """
    Blacklist for subdomain scanning
    Excluding too popular services not to overhelm scanning engine just by trying it on google, facebook, ...
    """
    __tablename__ = 'subdomain_scan_blacklist'
    id = Column(BigInteger, primary_key=True)
    rule = Column(String(255), nullable=False)  # usually domain suffix to match
    rule_type = Column(SmallInteger, default=0)  # suffix / exact / regex match

    detection_code = Column(SmallInteger, default=0)  # for auto-detection
    detection_value = Column(Integer, default=0)  # auto-detection threshold, e.g., 5000 certificates
    detection_first_at = Column(DateTime, default=None)  # first auto-detection
    detection_last_at = Column(DateTime, default=None)  # last auto-detection
    detection_num = Column(Integer, default=0)  # number of auto-detection triggers

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


class DbCrtShQueryInput(Base):
    """
    crt.sh search query input
    4 basic types: domain, *.domain, %.domain, RAW
    Identifies the particular search. Is used as a search key for the results search.
    """
    __tablename__ = 'crtsh_input'
    __table_args__ = (UniqueConstraint('iquery', 'itype', name='crtsh_input_key_unique'),)
    id = Column(BigInteger, primary_key=True)
    sld_id = Column(ForeignKey('base_domain.id', name='crtsh_input_base_domain_id', ondelete='SET NULL'),
                    nullable=True, index=True)  # SLD index, aux info for search

    iquery = Column(String(255), nullable=False)
    itype = Column(SmallInteger, default=0)
    created_at = Column(DateTime, default=None)


class DbCrtShQuery(Base):
    """
    crt.sh search query + results
    """
    __tablename__ = 'crtsh_query'
    id = Column(BigInteger, primary_key=True)
    job_id = Column(BigInteger, nullable=True)
    watch_id = Column(ForeignKey('watch_target.id', name='crtsh_watch_target_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner
    input_id = Column(ForeignKey('crtsh_input.id', name='crtsh_watch_input_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # input id - easy search, defines the search itself
    sub_watch_id = Column(ForeignKey('subdomain_watch_target.id', name='crtsh_watch_sub_target_id', ondelete='SET NULL'),
                          nullable=True, index=True)  # watch id scan for periodic sub domain scanner
    service_id = Column(ForeignKey('watch_service.id', name='crtsh_watch_watch_service_id', ondelete='SET NULL'),
                        nullable=True, index=True)  # ID of the service name

    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())

    status = Column(SmallInteger, default=0)  # response status, OK, timeout, error
    results = Column(Integer, default=0)
    new_results = Column(Integer, default=0)

    newest_cert_id = Column(BigInteger, nullable=True)  # updated from the last scan?
    newest_cert_sh_id = Column(BigInteger, nullable=True)  # updated from the last scan? raw id

    certs_ids = Column(Text, nullable=True)  # json encoded array of certificate ids, denormalized for efficiency.
    certs_sh_ids = Column(Text, nullable=True)  # json encoded array of certificate ids, denormalized for efficiency.


class DbCrtShQueryResult(Base):
    """
    Single response from the crtsh.
    Normalized version of results, used only for SQL searches, the main result table holds results also
    in JSON (denormalized copy) to avoid joins in normal operation.
    """
    __tablename__ = 'crtsh_query_results'
    id = Column(BigInteger, primary_key=True)

    query_id = Column(ForeignKey('crtsh_query.id', name='fk_crtsh_query_results_crtsh_query_id', ondelete='CASCADE'),
                      nullable=True, index=True)  # query ID foreign key
    job_id = Column(BigInteger, nullable=True)  # TODO: to foreign key

    crt_id = Column(BigInteger, nullable=True)
    crt_sh_id = Column(BigInteger, nullable=True)
    was_new = Column(SmallInteger, default=0)

    def __init__(self):
        self.cert_db = None


class DbHandshakeScanJob(Base):
    """
    TLS handshake scan, one single IP scan.
    """
    __tablename__ = 'scan_handshakes'
    id = Column(BigInteger, primary_key=True)

    job_id = Column(BigInteger, nullable=True)  # job id for web initiated scan
    watch_id = Column(ForeignKey('watch_target.id', name='tls_watch_target_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner

    ip_scanned = Column(String(255), nullable=True)  # ip address used to connect to (remote peer IP), ip also tied by watch id
    is_ipv6 = Column(SmallInteger, default=0, nullable=False)

    tls_ver = Column(String(16), nullable=True)  # tls version used to connect

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)

    status = Column(SmallInteger, default=0)
    err_code = Column(SmallInteger, default=0)  # basic error with the handshake (connect err / timeout / TLSAlert)
    tls_alert_code = Column(Integer, default=None)  # handshake error - tls alert code
    time_elapsed = Column(Integer, nullable=True)

    results = Column(Integer, default=0)      # num of certificates in the handshake
    new_results = Column(Integer, default=0)  # num of new certificates in the handshake

    certs_ids = Column(Text, nullable=True)  # json encoded array of certificate ids, denormalized for efficiency.
    cert_id_leaf = Column(BigInteger, nullable=True)  # id of the leaf certificate.
    valid_path = Column(SmallInteger, default=0)  # cert path validity test
    valid_hostname = Column(SmallInteger, default=0)  # hostname verifier check
    err_validity = Column(String(64), nullable=True)  # error with the path validity
    err_many_leafs = Column(SmallInteger, default=0)  # error with too many leafs in the handshake
    err_valid_ossl_code = Column(Integer, default=0)  # OSSL validation error code
    err_valid_ossl_depth = Column(Integer, default=0)  # depth of the certificate error

    sub_rsa = Column(ForeignKey('scan_sub_tls.id', name='scan_handshakes_scan_sub_tls_id_rsa', ondelete='SET NULL'),
                     nullable=True, index=True)  # sub tls scan for RSA
    sub_ecc = Column(ForeignKey('scan_sub_tls.id', name='scan_handshakes_scan_sub_tls_id_ecc', ondelete='SET NULL'),
                     nullable=True, index=True)  # sub tls scan for ECC

    req_https_result = Column(String(64), nullable=True)  # result of HTTPs req - no follow direct request
    follow_http_result = Column(String(64), nullable=True)  # result of HTTP req with follow redirects.
    follow_https_result = Column(String(64), nullable=True)  # result of HTTPs req with follow redirects
    follow_http_url = Column(String(255), nullable=True)  # URL after loading HTTP page
    follow_https_url = Column(String(255), nullable=True)  # URL after loading HTTPs page

    hsts_present = Column(SmallInteger, default=0)  # HSTS
    hsts_max_age = Column(BigInteger, nullable=True)  # HSTS
    hsts_include_subdomains = Column(SmallInteger, nullable=True)  # HSTS
    hsts_preload = Column(SmallInteger, nullable=True)  # HSTS

    pinning_present = Column(SmallInteger, default=0)  # Certificate pinning
    pinning_report_only = Column(SmallInteger, nullable=True)  # Certificate pinning
    pinning_pins = Column(Text, nullable=True)  # Certificate pinning, json encoded pins

    def __init__(self):
        self.trans_certs = {}
        self.trans_sub_res = []
        self.trans_validation_res = None


class DbSubTlsScan(Base):
    """
    TLS handshake scan, one single IP scan, sub scan (rsa/ecc, versions)
    """
    __tablename__ = 'scan_sub_tls'
    id = Column(BigInteger, primary_key=True)

    job_id = Column(BigInteger, nullable=True)  # job id for web initiated scan

    watch_id = Column(ForeignKey('watch_target.id', name='scan_sub_tls_watch_target_id',
                                 ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner

    parent_scan_id = Column(ForeignKey('scan_handshakes.id', name='scan_sub_tls_scan_handshakes_id',
                                       ondelete='SET NULL'),
                            nullable=True, index=True)  # watch id scan for periodic scanner

    # ip address used to connect to (remote peer IP), denormalized for easy query (fref by parent scan)
    ip_scanned = Column(String(255), nullable=True)
    is_ipv6 = Column(SmallInteger, default=0, nullable=False)

    # differentiating factors
    # tls version used to connect
    tls_ver = Column(String(16), nullable=True)  # SSL2, SSL3, ...
    key_type = Column(SmallInteger, default=0, nullable=True)  # RSA / ECC / DSS
    cipersuite_set = Column(BigInteger, default=0, nullable=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)

    status = Column(SmallInteger, default=0)
    err_code = Column(SmallInteger, default=0)  # basic error with the handshake (connect err / timeout / TLSAlert)
    tls_alert_code = Column(Integer, default=None)  # handshake error - tls alert code
    time_elapsed = Column(Integer, nullable=True)

    results = Column(Integer, default=0)      # num of certificates in the handshake
    new_results = Column(Integer, default=0)  # num of new certificates in the handshake

    certs_ids = Column(Text, nullable=True)  # json encoded array of certificate ids, denormalized for efficiency.
    cert_id_leaf = Column(BigInteger, nullable=True)  # id of the leaf certificate.
    valid_path = Column(SmallInteger, default=0)  # cert path validity test
    valid_hostname = Column(SmallInteger, default=0)  # hostname verifier check
    err_validity = Column(String(64), nullable=True)  # error with the path validity
    err_many_leafs = Column(SmallInteger, default=0)  # error with too many leafs in the handshake
    err_valid_ossl_code = Column(Integer, default=0)  # OSSL validation error code
    err_valid_ossl_depth = Column(Integer, default=0)  # depth of the certificate error


class DbHandshakeScanJobResult(Base):
    """
    Single certificate extracted from tls handshake scan.
    Normalized version of results, used only for SQL searches, the main result table holds results also
    in JSON (denormalized copy) to avoid joins in normal operation.
    """
    __tablename__ = 'scan_handshake_results'
    id = Column(BigInteger, primary_key=True)

    scan_id = Column(ForeignKey('scan_handshakes.id', name='fk_scan_handshake_results_scan_handshakes_id',
                                ondelete='CASCADE'), nullable=True, index=True)  # scan ID foreign key
    job_id = Column(BigInteger, nullable=True)  # TODO: to foreign key

    crt_id = Column(BigInteger, nullable=True)
    crt_sh_id = Column(BigInteger, nullable=True)
    was_new = Column(SmallInteger, default=0)
    is_ca = Column(SmallInteger, default=0)

    def __init__(self):
        self.trans_cert = None


class DbWatchTarget(Base):
    """
    Watching target - scan server host.
    Watch target is immutable w.r.t (scan_host, scan_scheme, scan_port)
     i.e., it has always the same ID for the results consistency.
    """
    __tablename__ = 'watch_target'
    id = Column(BigInteger, primary_key=True)

    scan_host = Column(String(255), nullable=False)
    scan_scheme = Column(String(255), nullable=True)
    scan_port = Column(String(255), nullable=True)
    scan_connect = Column(SmallInteger, default=0)  # TLS or STARTTLS

    # Explicit SNI / service name to scan on host if multiplexing.
    service_id = Column(ForeignKey('watch_service.id', name='wt_watch_service_id', ondelete='SET NULL'),
                        nullable=True, index=True)
    top_domain_id = Column(ForeignKey('base_domain.id', name='wt_base_domain_id', ondelete='SET NULL'),
                           nullable=True, index=True)
    agent_id = Column(ForeignKey('keychest_agent.id', name='wt_keychest_agent_id', ondelete='CASCADE'),
                      nullable=True, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last watcher processing of this entity (can do more indiv. scans)
    last_scan_state = Column(SmallInteger, default=0)  # watcher scanning running / finished

    # denormalization - optimized query
    last_dns_scan_id = Column(ForeignKey('scan_dns.id', name='wt_scan_dns_id', ondelete='SET NULL'),
                              nullable=True, index=True)
    
    def __init__(self):
        self.trans_service = None
        self.trans_top_domain = None


class DbUser(Base):
    """
    Users - Laravel maintained table!
    """
    __tablename__ = 'users'
    id = Column(INTEGER(10, unsigned=True), primary_key=True)
    name = Column(String(191), nullable=False)
    email = Column(String(191), nullable=False, unique=True)
    password = Column(String(191), nullable=True)
    remember_token = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=None)


class DbWatchAssoc(Base):
    """
    User -> Watch target association
    Enables to have watch_target id immutable to have valid results with target_id.
    Also helps with deduplication of watch target scans.
    """
    __tablename__ = 'user_watch_target'
    __table_args__ = (UniqueConstraint('user_id', 'watch_id', name='wa_user_watcher_uniqe'),)
    id = Column(BigInteger, primary_key=True)

    user_id = Column(ForeignKey('users.id', name='wa_users_id', ondelete='CASCADE'),
                     nullable=False, index=True)
    watch_id = Column(ForeignKey('watch_target.id', name='wa_watch_target_id', ondelete='CASCADE'),
                      nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    deleted_at = Column(DateTime, default=None, nullable=True)
    disabled_at = Column(DateTime, default=None, nullable=True)  # user disables this entry
    auto_scan_added_at = Column(DateTime, default=None, nullable=True)  # date of the auto-detection added this entry

    scan_periodicity = Column(BigInteger, nullable=True)
    scan_type = Column(Integer, nullable=True)


class DbBaseDomain(Base):
    """
    Base domain for whois lookup.
    """
    __tablename__ = 'base_domain'
    id = Column(BigInteger, primary_key=True)
    domain_name = Column(String(255), nullable=False, unique=True)


class DbWhoisCheck(Base):
    """
    Whois check results - aggregation possible
    """
    __tablename__ = 'whois_result'
    id = Column(BigInteger, primary_key=True)
    domain_id = Column(ForeignKey('base_domain.id', name='who_base_domain_id', ondelete='CASCADE'),
                       nullable=False, index=True)

    status = Column(SmallInteger, default=0)  # status code / error
    registrant_cc = Column(String(255), nullable=True)
    registrar = Column(String(255), nullable=True)
    registered_at = Column(DateTime, default=None, nullable=True)
    expires_at = Column(DateTime, default=None, nullable=True)
    dnssec = Column(SmallInteger, default=0)  # DNSsec enabled

    rec_updated_at = Column(DateTime, default=None, nullable=True)  # whois record updated at
    dns = Column(Text, default=None, nullable=True)
    emails = Column(Text, default=None, nullable=True)
    aux = Column(Text, default=None, nullable=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())

    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)
    domain = relationship("DbBaseDomain")


class DbScanHistory(Base):
    """
    Base scan history, RRD lvl 0, prune periodically.
    Keeps only last X records / weeks of records.
    On rotation results out of the window get accumulated to RRD lvl 1.
    """
    __tablename__ = "scan_history"
    id = Column(BigInteger, primary_key=True)
    watch_id = Column(ForeignKey('watch_target.id', name='shist_watch_target_id', ondelete='CASCADE'),
                      nullable=True, index=True)

    scan_code = Column(SmallInteger, nullable=False)  # tls / CT / whois / ...
    scan_type = Column(SmallInteger, nullable=True)  # scan subtype - full handshake, ciphersuites...
    created_at = Column(DateTime, default=None)


class DbScanGaps(Base):
    """
    Gaps in the scannings above defined SLA.
    Periodic scans are assumed to be run in the SLA period - e.g., if SLA 1 hour,
    we would like to guarantee at least 1 scan in 1 hour. If this scan
    is voilated due to something we have to have a record about it - gap in scanning.
    If there is no gap record it is assumed SLA was not violated. Scans stores only
    result that changes over time.
    """
    __tablename__ = "scan_gaps"
    id = Column(BigInteger, primary_key=True)
    watch_id = Column(ForeignKey('watch_target.id', name='sgap_watch_target_id', ondelete='CASCADE'),
                      nullable=True, index=True)

    scan_code = Column(SmallInteger, nullable=False)  # tls / CT / whois / ...
    scan_type = Column(SmallInteger, nullable=True)  # scan subtype - full handshake, ciphersuites...
    created_at = Column(DateTime, default=None)
    gap_start = Column(DateTime, default=None)
    gap_end = Column(DateTime, default=None)


class DbSystemLastEvents(Base):
    """
    System events table - stores watchdog ticks / network working ticks.
    If server crashes it can detect how long it has been out.
    Stores only last occurrence of the event.
    """
    __tablename__ = "system_last_events"
    id = Column(BigInteger, primary_key=True)
    event_key = Column(String(191), nullable=False, unique=True)
    event_at = Column(DateTime, default=None)
    aux = Column(Text, default=None, nullable=True)


class DbLastRecordCache(Base):
    """
    Optimization table for fetching last record for some key - e.g.,
    last scan for the given watcher.
    """
    __tablename__ = "last_record_cache"
    id = Column(BigInteger, primary_key=True)
    record_key = Column(String(191), nullable=False, unique=True)
    record_at = Column(DateTime, default=None)
    record_id = Column(BigInteger, default=None)
    record_aux = Column(Text, default=None, nullable=True)
    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


class DbLastScanCache(Base):
    """
    Last scan cache - in order to avoid complicated sub-queries.
    """
    __tablename__ = "last_scan_cache"
    __table_args__ = (UniqueConstraint('cache_type', 'obj_id', 'scan_type', 'scan_sub_type', 'aux_key',
                                       name='uq_last_scan_cache_key'),)
    id = Column(BigInteger, primary_key=True)

    cache_type = Column(SmallInteger, default=0, nullable=False)  # mostly 0
    obj_id = Column(BigInteger, default=0, index=True)  # watch_id mostly, or service_id, local_service

    scan_type = Column(Integer, default=0, nullable=False, index=True)  # tls, dns, crtsh, wildcard, subs, ...
    scan_sub_type = Column(Integer, default=0, nullable=False)

    aux_key = Column(String(191), default='', nullable=False)  # mostly empty string or IP

    scan_id = Column(BigInteger, default=None, nullable=False)
    scan_aux = Column(Text, default=None, nullable=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


class DbDnsResolve(Base):
    """
    DNS resolve results
    """
    __tablename__ = "scan_dns"
    id = Column(BigInteger, primary_key=True)

    job_id = Column(BigInteger, nullable=True)  # job id for web initiated scan
    watch_id = Column(ForeignKey('watch_target.id', name='dns_watch_target_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)

    status = Column(SmallInteger, default=0)

    num_res = Column(SmallInteger, default=0, nullable=False)
    num_ipv4 = Column(SmallInteger, default=0, nullable=False)
    num_ipv6 = Column(SmallInteger, default=0, nullable=False)
    dns = Column(Text, nullable=True)  # normalized json with dns results

    def __init__(self):
        self.dns_res = []
        self.dns_status = 0

    @orm.reconstructor
    def init_on_load(self):
        self.dns_res = util.defval(util.try_load_json(self.dns), [])
        self.dns_status = self.status


class DbDnsEntry(Base):
    """
    DNS normalized dns entry on getaddressinfo()
    Used for DB searches, joins & multiple IP TLS scan support.

    dns scan -> dns entry
    """
    __tablename__ = "scan_dns_entry"
    id = Column(BigInteger, primary_key=True)
    scan_id = Column(ForeignKey('scan_dns.id', name='scan_dns_entry_scan_id', ondelete='CASCADE'),
                     nullable=False, index=True)

    is_ipv6 = Column(SmallInteger, default=0, nullable=False)
    is_internal = Column(SmallInteger, default=0, nullable=False)
    ip = Column(String(191), nullable=False, index=True)
    res_order = Column(SmallInteger, default=0, nullable=False)


class DbSubdomainWatchTarget(Base):
    """
    Watching target for subdomain auto-detection.
    """
    __tablename__ = 'subdomain_watch_target'
    id = Column(BigInteger, primary_key=True)

    scan_host = Column(String(255), nullable=False)
    scan_ports = Column(Text, nullable=True)  # optional, json encoded port list for basic liveness check

    top_domain_id = Column(ForeignKey('base_domain.id', name='sub_wt_base_domain_id', ondelete='SET NULL'),
                           nullable=True, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last watcher processing of this entity (can do more indiv. scans)
    last_scan_state = Column(SmallInteger, default=0)  # watcher scanning running / finished


class DbSubdomainWatchAssoc(Base):
    """
    User -> subdomain Watch target association
    Enables to have watch_target id immutable to have valid results with target_id.
    Also helps with deduplication of watch target scans.
    """
    __tablename__ = 'user_subdomain_watch_target'
    __table_args__ = (UniqueConstraint('user_id', 'watch_id', name='wa_user_sub_watcher_uniqe'),)
    id = Column(BigInteger, primary_key=True)

    user_id = Column(ForeignKey('users.id', name='wa_sub_users_id', ondelete='CASCADE'),
                     nullable=False, index=True)
    watch_id = Column(ForeignKey('subdomain_watch_target.id', name='wa_sub_watch_target_id', ondelete='CASCADE'),
                      nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    deleted_at = Column(DateTime, default=None, nullable=True)
    disabled_at = Column(DateTime, default=None, nullable=True)
    auto_scan_added_at = Column(DateTime, default=None, nullable=True)

    scan_periodicity = Column(BigInteger, nullable=True)
    scan_type = Column(Integer, nullable=True)
    auto_fill_watches = Column(SmallInteger, default=0, nullable=False)  # if 1 new hosts will be converted to active watches


class DbSubdomainResultCache(Base):
    """
    Caching subdomain enumeration scan results.
    Distilled results from CT downloaded certificates.

    watch -> subdomains results
    """
    __tablename__ = 'subdomain_results'
    id = Column(BigInteger, primary_key=True)

    watch_id = Column(ForeignKey('subdomain_watch_target.id', name='wa_sub_res_watch_target_id', ondelete='CASCADE'),
                      nullable=False, index=True)

    scan_type = Column(SmallInteger, default=0)  # CT log / sublist3r / subbrute / ...
    scan_status = Column(SmallInteger, default=0)  # result code of the scan

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    last_scan_idx = Column(BigInteger, nullable=True)  # newest element in the scan, e.g., certificate ID
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)

    result_size = Column(Integer, default=0, nullable=False)
    result = Column(Text, nullable=True)  # JSON result data, normalized for easy comparison. Sorted list of subdomains.

    def __init__(self):
        self.trans_result = []  # transient value of unserialized json

    @orm.reconstructor
    def init_on_load(self):
        self.trans_result = util.defval(util.try_load_json(self.result), [])


class DbSubdomainWatchResultEntry(Base):
    """
    Caching subdomain enumeration scan result - separate entry. Normalized entry.
    Used for DB searches, joins & multiple IP support.

    watch -> dns entry

    Does not relate directly to the particular result as there might be a gap - in case we need it we can add
    another mapping table subres -> entry.
    """
    __tablename__ = "subdomain_watch_result_entry"
    id = Column(BigInteger, primary_key=True)

    # After conversion to service id this will be obsolete, substituted by service_id
    watch_id = Column(ForeignKey('subdomain_watch_target.id', name='subdom_watch_entry_watch_id', ondelete='CASCADE'),
                      nullable=False, index=True)
    service_id = Column(ForeignKey('watch_service.id', name='subdom_watch_entry_service_id', ondelete='CASCADE'),
                        nullable=True, index=True)

    is_wildcard = Column(SmallInteger, default=0, nullable=False)
    is_internal = Column(SmallInteger, default=0, nullable=False)
    is_long = Column(SmallInteger, default=0, nullable=False)  # too long, text

    name = Column(String(191), nullable=False, index=True)
    name_full = Column(Text, nullable=True)
    res_order = Column(SmallInteger, default=0, nullable=False)

    created_at = Column(DateTime, default=None)  # usually date of the first detection
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1, nullable=False)  # number of scans with this result (periodic scanner)

    last_scan_id = Column(ForeignKey('subdomain_results.id', name='subdom_watch_entry_subdomain_results_id_first',
                                     ondelete='SET NULL'), nullable=True, index=True)
    first_scan_id = Column(ForeignKey('subdomain_results.id', name='subdom_watch_entry_subdomain_results_id_last',
                                      ondelete='SET NULL'), nullable=True, index=True)


class DbOrganization(Base):
    """
    Base organization record
    """
    __tablename__ = "organization"
    id = Column(BigInteger, primary_key=True)
    name = Column(String(191), nullable=False)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


class DbOrganizationGroup(Base):
    """
    Sub organization group.

    organization -> organization group
    """
    __tablename__ = "organization_group"
    id = Column(BigInteger, primary_key=True)
    name = Column(String(191), nullable=False)

    organization_id = Column(ForeignKey('organization.id', name='organization_group_organization_id',
                                        ondelete='CASCADE'), nullable=False, index=True)

    parent_group_id = Column(ForeignKey('organization_group.id', name='organization_group_organization_group_id',
                                        ondelete='SET NULL'), nullable=True, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


class DbKeychestAgent(Base):
    """
    Keychest agent record - identifies particular keychest slave instance
    """
    __tablename__ = "keychest_agent"
    id = Column(BigInteger, primary_key=True)
    name = Column(String(191), nullable=False)
    api_key = Column(String(191), nullable=False, index=True)

    organization_id = Column(ForeignKey('organization.id', name='keychest_agent_organization_id',
                                        ondelete='CASCADE'), nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_seen_active_at = Column(DateTime, default=None)  # last
    last_seen_ip = Column(String(191), nullable=True)


class DbWatchService(Base):
    """
    Defines a service to watch.

    Represents the particular service name the keychest is testing, unrelated
    to the physical location (server). It can be a SNI name on multiplexed host.

    CT scans are related to the service name (domain / web).
    There is usually one-to-many relation service -> target (target as a physical machine / server).

    This is meant to be a global service reference, e.g. for CT log scanning & whois.
    It is global object, unrelated to the users.
    """
    __tablename__ = 'watch_service'
    id = Column(BigInteger, primary_key=True)

    service_name = Column(String(255), nullable=False, unique=True)
    top_domain_id = Column(ForeignKey('base_domain.id', name='watch_service_base_domain_id', ondelete='SET NULL'),
                           nullable=True, index=True)
    crtsh_input_id = Column(ForeignKey('crtsh_input.id', name='fk_watch_service_crtsh_input_id', ondelete='SET NULL'),
                            nullable=True, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())

    last_scan_at = Column(DateTime, default=None)  # last watcher processing of this entity (can do more indiv. scans)
    last_scan_state = Column(SmallInteger, default=0)  # watcher scanning running / finished

    def __init__(self):
        self.trans_top_domain = None
        self.trans_crtsh_input = None


class DbWatchLocalService(Base):
    """
    Defines a local service to watch.
    Local service is related to the agent, thus to the organization.
    """
    __tablename__ = 'watch_local_service'
    id = Column(BigInteger, primary_key=True)

    service_id = Column(ForeignKey('watch_service.id', name='watch_local_service_watch_service_id', ondelete='CASCADE'),
                        nullable=False, index=True)
    agent_id = Column(ForeignKey('keychest_agent.id', name='watch_local_service_keychest_agent_id', ondelete='CASCADE'),
                      nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


#
# DB helper objects
#  - query building, model comparison, projections
#


class TransientCol(object):
    """
    Represents transient column for model projection and comparison.
    """
    def __init__(self, name, default=None):
        self.name = name
        self.default = default


class ColTransformWrapper(object):
    """
    Simple column wrapper - for transformation
    """
    __slots__ = ('_col', '_tran')

    def __init__(self, col, transform=None):
        self._col = col
        self._tran = transform

    def transform(self, val):
        if self._tran:
            return self._tran(val)
        return val

    @property
    def col(self):
        return self._col

    def __getitem__(self, item):
        return self._col[item]

    def __getattr__(self, item):
        if item in self.__slots__:
            return object.__getattr__(self, item)
        return getattr(self._col, item)

    def __setattr__(self, key, value):
        if key in self.__slots__:
            return object.__setattr__(self, key, value)
        return setattr(self._col, key, value)

    def __repr__(self):
        return repr(self._col)


class DbHelper(object):
    """
    Helper methods
    """
    @staticmethod
    def default_value(col):
        """
        Returns default value from the column
        :param col:
        :return:
        """
        if col is None or col.default is None:
            return None

        if isinstance(col.default, ColumnDefault) and col.default.is_scalar:
            return col.default.arg

        if isinstance(col, TransientCol):
            return col.default

        return None

    @staticmethod
    def default_model(obj, projection=None, clone=False):
        """
        Fills in default model data from the passed object - fills in missing values.
        If projection is given the model is projected. Does not support function defaults.
        :param obj: object to fill in default values to
        :param projection: iterable of columns to check for the default value
        :param clone: if true the result is deepcloned from the original - does not modify the original object
        :return:
        """
        if obj is None:
            return None

        if clone:
            obj = copy.deepcopy(obj)

        cols = projection
        if cols is None or len(cols) == 0:
            cols = obj.__table__.columns

        for col in cols:
            val = getattr(obj, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            if val is None:
                def_val = DbHelper.default_value(col)
                if def_val is not None:
                    val = copy.deepcopy(def_val)
                    if isinstance(col, ColTransformWrapper):
                        val = col.transform(val)
                    setattr(obj, col.name, val)

        return obj

    @staticmethod
    def project_model(obj, projection, default_vals=False):
        """
        Projection returns tuple of the columns in the projection.
        :param obj:
        :param projection: iterable of columns to take to the projection
        :param default_vals: sets default values
        :return:
        """
        ret = []
        if obj is None:
            return None

        if projection is None or len(projection) == 0:
            return ()

        for col in projection:
            val = getattr(obj, col.name)
            if default_vals and val is None:
                def_val = DbHelper.default_value(col)
                if def_val is not None:
                    val = copy.deepcopy(def_val)

            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)
            ret.append(val)
        return tuple(ret)

    @staticmethod
    def query_filter_model(q, cols, obj):
        """
        Adds filter to the query based on the cols & model
        :param q:
        :param cols:
        :param obj:
        :return:
        """
        for col in cols:
            val = getattr(obj, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            q = q.filter(col == val)
        return q

    @staticmethod
    def model_to_cmp_tuple(x, cols):
        """
        Returns model tuple for comparison, defined by cols projection
        :param x:
        :param cols:
        :return:
        """
        if x is None:
            return None
        return DbHelper.project_model(x, cols, default_vals=True)

    @staticmethod
    def models_tuples(x, y, cols):
        """
        Converts models to comparison tuples defined by the projection
        :param x:
        :param y:
        :param cols:
        :return:
        """
        return DbHelper.model_to_cmp_tuple(x, cols), DbHelper.model_to_cmp_tuple(y, cols)

    @staticmethod
    def models_tuples_compare(x, y, cols):
        """
        Converts models to comparison tuples defined by the projection and compares them
        :param x:
        :param y:
        :param cols:
        :return:
        """
        t1, t2 = DbHelper.models_tuples(x, y, cols)
        return t1 == t2

    @staticmethod
    def update_model_null_values(dst, src, cols):
        """
        Updates all fields with null values in dst from src defined by cols
        :param dst:
        :param src:
        :param cols:
        :return: number of changes
        """
        ret = []
        if dst is None or src is None:
            return 0

        if cols is None or len(cols) == 0:
            return 0

        changes = 0
        for col in cols:
            val = getattr(src, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            dstval = getattr(dst, col.name)
            if isinstance(col, ColTransformWrapper):
                dstval = col.transform(dstval)

            if dstval is None:
                setattr(dst, col.name, val)

            changes += 1
        return changes

    @staticmethod
    def yield_limit(qry, pk_attr, maxrq=100):
        """specialized windowed query generator (using LIMIT/OFFSET)

        This recipe is to select through a large number of rows thats too
        large to fetch at once. The technique depends on the primary key
        of the FROM clause being an integer value, and selects items
        using LIMIT."""

        firstid = None
        while True:
            q = qry
            if firstid is not None:
                q = qry.filter(pk_attr > firstid)
            rec = None
            for rec in q.order_by(pk_attr).limit(maxrq):
                yield rec
            if rec is None:
                break
            firstid = pk_attr.__get__(rec, pk_attr) if rec else None

    @staticmethod
    def get_count(q):
        """
        Gets count(*) from the given query, faster than .count() method:
         - q.count()      SELECT COUNT(*) FROM (SELECT ... FROM TestModel WHERE ...) ...
         - get_count(q)   SELECT COUNT(*) FROM TestModel WHERE ...
        :param q:
        :return:
        """
        count_q = q.statement.with_only_columns([func.count()]).order_by(None)
        count = q.session.execute(count_q).scalar()
        return count

    @staticmethod
    def to_dict(model, cols=None):
        """
        Transforms model to a dictionary
        :param model:
        :param cols:
        :return:
        """
        if model is None:
            return None

        obj = copy.deepcopy(model)
        if cols is None:
            cols = model.__table__.columns
        ret = collections.OrderedDict()

        for col in cols:
            val = getattr(obj, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            if val is None:
                def_val = DbHelper.default_value(col)
                if def_val is not None:
                    val = copy.deepcopy(def_val)
                    if isinstance(col, ColTransformWrapper):
                        val = col.transform(val)

            ret[col.name] = val
        return ret


class ResultModelUpdater(object):
    @staticmethod
    def insert_or_update(s, select_cols, cmp_cols, obj,
                         last_scan_update_fnc=None,
                         obj_update_fnc=None):
        """
        Works on a generic results model changing diffs.
        Selects model from DB using select_cols, based on obj table.
        required columns: last_scan_at, num_scans for result aggregation
        :param s:
        :param select_cols:
        :param cmp_cols:
        :param obj:
        :param last_scan_update_fnc:
        :param obj_update_fnc:
        :return:
        """
        q = s.query(obj.__class__)
        q = DbHelper.query_filter_model(q, select_cols, obj)
        q = q.order_by(obj.__class__.last_scan_at.desc()).limit(1)

        last_scan = q.first()
        is_same = DbHelper.models_tuples_compare(obj, last_scan, cmp_cols)
        if is_same:
            last_scan.last_scan_at = sa.func.now()
            last_scan.num_scans += 1
            if last_scan_update_fnc is not None:
                last_scan_update_fnc(last_scan)

        else:
            obj.num_scans = 1
            obj.updated_ad = sa.func.now()
            obj.last_scan_at = sa.func.now()
            if obj_update_fnc is not None:
                obj_update_fnc(obj, last_scan=last_scan)
            s.add(obj)
        s.commit()

        return is_same, obj, last_scan

    @staticmethod
    def update_cache(s, new_scan, sub_type=0, cache_type=0, skip_search=False):
        """
        Updates last scan cache
        :param s:
        :param new_scan:
        :param sub_type:
        :param cache_type:
        :param skip_search:
        :return:
        """
        cache = DbLastScanCache()
        cache.cache_type = cache_type
        cache.scan_sub_type = sub_type
        cache.aux_key = ''  # mostly empty string or IP
        cache.scan_id = new_scan.id
        cache.created_at = sa.func.now()
        cache.updated_at = sa.func.now()

        if isinstance(new_scan, DbHandshakeScanJob):
            cache.obj_id = new_scan.watch_id
            cache.scan_type = DbScanType.TLS
            cache.aux_key = new_scan.ip_scanned

        elif isinstance(new_scan, DbDnsResolve):
            cache.obj_id = new_scan.watch_id
            cache.scan_type = DbScanType.DNS

        elif isinstance(new_scan, DbCrtShQuery):
            cache.obj_id = new_scan.watch_id
            cache.scan_type = DbScanType.CRTSH

        elif isinstance(new_scan, DbSubdomainResultCache):
            cache.obj_id = new_scan.watch_id
            cache.scan_type = DbScanType.SUBS

        elif isinstance(new_scan, DbWhoisCheck):
            cache.obj_id = new_scan.domain_id
            cache.scan_type = DbScanType.WHOIS

        else:
            raise ValueError('Unrecognized scan result, cannot persist')

        try:
            should_add = skip_search
            if not skip_search:
                m = DbLastScanCache
                cols = [m.cache_type, m.obj_id, m.scan_type, m.scan_sub_type, m.aux_key]

                q = s.query(DbLastScanCache)
                q = DbHelper.query_filter_model(q, cols, cache)
                cc = q.first()

                if cc:
                    cc.scan_id = cache.scan_id
                    cc.scan_aux = cache.scan_aux
                    s.commit()
                else:
                    should_add = True

            if should_add:
                s.add(cache)
                s.commit()

        except Exception as e:
            logger.debug('Exception storing last record cache: %s' % e)
            s.rollback()


class assign(expression.FunctionElement):
    name = 'assign'


# @compiles(assign)
# def generic_assign(element, compiler, **kw):
#     raise ValueError('Unsupported engine')


@compiles(assign)
def mysql_assign(element, compiler, **kw):
    arg1, arg2 = list(element.clauses)
    return "@%s := %s" % (
        compiler.process(arg1),
        compiler.process(arg2)
    )


#
# MySQL engine management class
#


class MySQL(object):
    """
    MySQL management, installation & stuff
    """

    PORT = 3306
    HOST = '127.0.0.1'

    def __init__(self, config=None, *args, **kwargs):
        self.config = config
        self.engine = None
        self.session = None

        self.secure_config = None
        self.secure_query = None

    def get_connstring(self):
        """
        Returns connection string to the MySQL database for root.
        :return:
        """
        con_string = 'mysql://%s:%s@%s%s/%s' % (self.config.mysql_user, self.config.mysql_password,
                                                self.HOST, ':%s' % self.PORT,
                                                self.config.mysql_db)
        return con_string

    def build_engine(self, connstring=None, user=None, password=None, store_as_main=True):
        """
        Returns root SQLAlchemy engine.
        :param connstring: connection string. if empty, default root is used
        :param user: user to use for the engine, if connstring is not given, local database is used
        :param password: user password to use for the engine, if connstring is not given, local database is used
        :return:
        """
        try:
            filterwarnings('ignore', category=MySQLDatabase.Warning)
            filterwarnings('ignore', category=sa_exc.SAWarning)

            con_str = connstring
            if con_str is None and user is not None:
                con_str = 'mysql://%s:%s@%s%s' % (user, password, self.HOST, ':%s' % self.PORT)
            if con_str is None and password is not None:
                con_str = 'mysql://%s:%s@%s%s' % ('root', password, self.HOST, ':%s' % self.PORT)
            if con_str is None:
                con_str = self.get_connstring()

            engine = create_engine(con_str, pool_size=200, max_overflow=32, pool_recycle=3600)
            if store_as_main:
                self.engine = engine

            return engine

        except Exception as e:
            logger.info('Exception in building MySQL DB engine %s' % e)
            raise

    def init_db(self):
        """
        Initializes internal database
        :return:
        """
        self.build_engine()
        self.session = scoped_session(sessionmaker(bind=self.engine))

        # Make sure tables are created
        Base.metadata.create_all(self.engine)

    def get_session(self):
        """
        Returns a new session
        :return:
        :rtype scoped_session
        """
        return self.session()

    def get_engine(self):
        """
        Returns engine.
        :return:
        """
        return self.engine

    def execute_sql(self, sql, engine=None, ignore_fail=False):
        """
        Executes SQL query on the engine, logs the query
        :param engine:
        :param sql:
        :param user: user performing the query, just for auditing purposes
        :param ignore_fail: if true mysql error is caught and logged
        :return:
        """
        res = None
        result_code = 0
        try:
            if engine is None:
                engine = self.engine

            res = engine.execute(sql)
            return res

        except Exception as e:
            result_code = 1
            logger.debug('Exception in sql: %s, %s' % (sql, e))
            if not ignore_fail:
                raise

        return None

