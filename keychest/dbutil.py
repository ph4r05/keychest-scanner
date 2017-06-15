#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import util
import errors
import logging

from sqlalchemy import create_engine, UniqueConstraint
from sqlalchemy import exc as sa_exc
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, query
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import INTEGER
from warnings import filterwarnings
import MySQLdb as MySQLDatabase


"""
Basic database utils.
"""

logger = logging.getLogger(__name__)

# Base for schema definitions
Base = declarative_base()


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


class Certificate(Base):
    """
    Certificate object
    """
    __tablename__ = 'certificates'
    id = Column(BigInteger, primary_key=True)
    crt_sh_id = Column(BigInteger, index=True, nullable=True)
    crt_sh_ca_id = Column(BigInteger, nullable=True)

    fprint_sha1 = Column(String(40), index=True, nullable=True)
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

    alt_names = Column(Text, nullable=True)  # json encoded alt names array. denormalized for efficiency

    source = Column(String(255), nullable=True)  # CT / crt.sh / manual

    pem = Column(Text, nullable=True)


class CertificateAltName(Base):
    """
    Certificate alt names, simple association table to certificate for DB based search.
    Normalized version of alt names, used only for SQL searches, the certificate table holds alt names also
    in JSON (denormalized copy) to avoid joins in normal operation.
    """
    __tablename__ = 'certificate_alt_names'
    cert_id = Column(BigInteger, index=True, primary_key=True)
    alt_name = Column(String(255), index=True, primary_key=True, nullable=False)


class DbCrtShQuery(Base):
    """
    crt.sh search query + results
    """
    __tablename__ = 'crtsh_query'
    id = Column(BigInteger, primary_key=True)
    job_id = Column(BigInteger, nullable=True)

    created_at = Column(DateTime, default=None)
    status = Column(SmallInteger, default=0)
    results = Column(Integer, default=0)
    new_results = Column(Integer, default=0)

    certs_ids = Column(Text, nullable=True)  # json encoded array of certificate ids, denormalized for efficiency.


class DbCrtShQueryResult(Base):
    """
    Single response from the crtsh.
    Normalized version of results, used only for SQL searches, the main result table holds results also
    in JSON (denormalized copy) to avoid joins in normal operation.
    """
    __tablename__ = 'crtsh_query_results'
    id = Column(BigInteger, primary_key=True)
    query_id = Column(BigInteger)
    job_id = Column(BigInteger, nullable=True)

    crt_id = Column(BigInteger, nullable=True)
    crt_sh_id = Column(BigInteger, nullable=True)
    was_new = Column(SmallInteger, default=0)


class DbHandshakeScanJob(Base):
    """
    TLS handshake scan, one single IP scan.
    """
    __tablename__ = 'scan_handshakes'
    id = Column(BigInteger, primary_key=True)

    job_id = Column(BigInteger, nullable=True)  # job id for web initiated scan
    watch_id = Column(ForeignKey('watch_target.id'), nullable=True, index=True)  # watch id scan for periodic scanner

    ip_scanned = Column(String(255), nullable=True)  # ip address used to connect to (remote peer IP)
    tls_ver = Column(String(16), nullable=True)  # tls version used to connect

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)

    status = Column(SmallInteger, default=0)
    err_code = Column(SmallInteger, default=0)  # basic error with the handshake (connect err / timeout / TLSAlert)
    time_elapsed = Column(Integer, nullable=True)

    results = Column(Integer, default=0)      # num of certificates in the handshake
    new_results = Column(Integer, default=0)  # num of new certificates in the handshake

    certs_ids = Column(Text, nullable=True)  # json encoded array of certificate ids, denormalized for efficiency.
    cert_id_leaf = Column(BigInteger, nullable=True)  # id of the leaf certificate.
    valid_path = Column(SmallInteger, default=0)  # cert path validity test
    valid_hostname = Column(SmallInteger, default=0)  # hostname verifier check
    err_validity = Column(String(64), default=0)  # error with the path validity
    err_many_leafs = Column(SmallInteger, default=0)  # error with too many leafs in the handshake

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


class DbHandshakeScanJobResult(Base):
    """
    Single certificate extracted from tls handshake scan.
    Normalized version of results, used only for SQL searches, the main result table holds results also
    in JSON (denormalized copy) to avoid joins in normal operation.
    """
    __tablename__ = 'scan_handshake_results'
    id = Column(BigInteger, primary_key=True)
    scan_id = Column(BigInteger)
    job_id = Column(BigInteger, nullable=True)

    crt_id = Column(BigInteger, nullable=True)
    crt_sh_id = Column(BigInteger, nullable=True)
    was_new = Column(SmallInteger, default=0)
    is_ca = Column(SmallInteger, default=0)


class DbWatchTarget(Base):
    """
    Watching target - scan server host
    """
    __tablename__ = 'watch_target'
    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, nullable=True)

    scan_host = Column(String(255), nullable=False)
    scan_scheme = Column(String(255), nullable=True)
    scan_port = Column(String(255), nullable=True)
    scan_periodicity = Column(BigInteger, nullable=True)  # deprecated, moved to association
    scan_connect = Column(SmallInteger, default=0)  # TLS or STARTTLS

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last watcher processing of this entity (can do more indiv. scans)
    last_scan_state = Column(SmallInteger, default=0)  # watcher scanning running / finished


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
    __table_args__ = (UniqueConstraint('user_id', 'watch_id', name='_user_watcher_uniqe'),)
    id = Column(BigInteger, primary_key=True)

    user_id = Column(ForeignKey('users.id'), nullable=False, index=True)
    watch_id = Column(ForeignKey('watch_target.id'), nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    deleted_at = Column(DateTime, default=None, nullable=True)

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
    domain_id = Column(ForeignKey('base_domain.id'), nullable=False, index=True)
    registrant_cc = Column(String(255), nullable=True)
    registrar = Column(String(255), nullable=True)
    registered_at = Column(DateTime, default=None, nullable=True)
    expires_at = Column(DateTime, default=None, nullable=True)
    rec_updated_at = Column(DateTime, default=None, nullable=True)  # whois record updated at
    dns = Column(Text, default=None, nullable=True)
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
    watch_id = Column(ForeignKey('watch_target.id'), nullable=True, index=True)
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
    watch_id = Column(ForeignKey('watch_target.id'), nullable=True, index=True)
    scan_code = Column(SmallInteger, nullable=False)  # tls / CT / whois / ...
    scan_type = Column(SmallInteger, nullable=True)  # scan subtype - full handshake, ciphersuites...
    created_at = Column(DateTime, default=None)
    gap_start = Column(DateTime, default=None)
    gap_end = Column(DateTime, default=None)


class DbSystemLastEvents(Base):
    """
    System events table - stores watchdog ticks / network working ticks.
    If server crashes it can detect how long it has been out.
    Stores only last occurence of the event.
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

            engine = create_engine(con_str, pool_recycle=3600)
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

