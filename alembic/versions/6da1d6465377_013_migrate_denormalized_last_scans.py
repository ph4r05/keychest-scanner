"""013 migrate denormalized last scans

Revision ID: 6da1d6465377
Revises: 99b3bef9ff03
Create Date: 2017-07-10 12:56:53.845288

"""
from alembic import op
from alembic import context

import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy import event, UniqueConstraint, orm
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session as BaseSession, relationship, scoped_session

import logging
import sys
from keychest import util
from keychest import util_cert
from keychest.tls_domain_tools import TlsDomainTools
from keychest.dbutil import DbHelper, ResultModelUpdater
from keychest.consts import DbScanType


# revision identifiers, used by Alembic.
revision = '6da1d6465377'
down_revision = '99b3bef9ff03'
branch_labels = None
depends_on = None


Base = declarative_base()
logger = logging.getLogger(__name__)


#
# Base classes for data migration
#


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


class DbCrtShQuery(Base):
    """
    crt.sh search query + results
    """
    __tablename__ = 'crtsh_query'
    id = Column(BigInteger, primary_key=True)
    job_id = Column(BigInteger, nullable=True)
    watch_id = Column(ForeignKey('watch_target.id', name='crtsh_watch_target_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner

    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


class DbHandshakeScanJob(Base):
    """
    TLS handshake scan, one single IP scan.
    """
    __tablename__ = 'scan_handshakes'
    id = Column(BigInteger, primary_key=True)

    job_id = Column(BigInteger, nullable=True)  # job id for web initiated scan
    watch_id = Column(ForeignKey('watch_target.id', name='tls_watch_target_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner

    ip_scanned = Column(String(255), nullable=True)  # ip address used to connect to (remote peer IP)
    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)


class DbWatchTarget(Base):
    """
    Watching target - scan server host.
    Watch target is immutable w.r.t (scan_host, scan_scheme, scan_port)
     i.e., it has always the same ID for the results consistency.
    """
    __tablename__ = 'watch_target'
    id = Column(BigInteger, primary_key=True)


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

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())

    last_scan_at = Column(DateTime, default=None)  # last scan with this result (periodic scanner)
    num_scans = Column(Integer, default=1)  # number of scans with this result (periodic scanner)


class DbSubdomainWatchTarget(Base):
    """
    Watching target for subdomain auto-detection.
    """
    __tablename__ = 'subdomain_watch_target'
    id = Column(BigInteger, primary_key=True)


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

    result = Column(Text, nullable=True)  # JSON result data, normalized for easy comparison. Sorted list of subdomains.

    def __init__(self):
        self.trans_result = []  # transient value of unserialized json

    @orm.reconstructor
    def init_on_load(self):
        self.trans_result = util.defval(util.try_load_json(self.result), [])


class DbLastScanCache(Base):
    """
    Last scan cache - in order to avoid complicated sub-queries.
    """
    __tablename__ = "last_scan_cache"
    __table_args__ = (UniqueConstraint('cache_type', 'obj_id', 'scan_type', 'scan_sub_type', 'aux_key',
                                       name='uq_last_scan_cache_key'),)
    id = Column(BigInteger, primary_key=True)

    cache_type = Column(SmallInteger, default=0, nullable=False)  # mostly 0
    obj_id = Column(BigInteger, default=0)  # watch_id mostly, or service_id, local_service

    scan_type = Column(Integer, default=0, nullable=False)  # tls, dns, crtsh, wildcard, subs, ...
    scan_sub_type = Column(Integer, default=0, nullable=False)

    aux_key = Column(String(191), default='', nullable=False)  # mostly empty string or IP

    scan_id = Column(BigInteger, default=None, nullable=False)
    scan_aux = Column(Text, default=None, nullable=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


#
# Data migration
#


def flush_cache(s):
    """
    Delete all previous entries to simplify migration. This is corner case for dev server only.
    On production the table will be created just second ago this migration script is run.
    :param s:
    :return:
    """
    s.query(DbLastScanCache).delete()
    # s.commit()


def add_cache(s, new_scan):
    """
    Inserts the cache record
    :param s:
    :param rec:
    :return:
    """
    if new_scan is None:
        return

    cache = DbLastScanCache()
    cache.cache_type = 0
    cache.obj_id = 0  # watch_id mostly, or service_id, local_service
    cache.scan_type = 0  # tls, dns, crtsh, wildcard, subs, ...
    cache.scan_sub_type = 0
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

    s.add(cache)


def watch_based(s):
    """
    Watch_id based results lookup
    :param s:
    :return:
    """
    targets = s.query(DbWatchTarget).all()
    for watch in targets:
        q = s.query(DbCrtShQuery).filter(DbCrtShQuery.watch_id == watch.id)
        crtsh = q.order_by(DbCrtShQuery.last_scan_at.desc()).limit(1).first()  # type: DbCrtShQuery
        add_cache(s, crtsh)

        q = s.query(DbDnsResolve).filter(DbDnsResolve.watch_id == watch.id)
        dns = q.order_by(DbDnsResolve.last_scan_at.desc()).limit(1).first()  # type: DbDnsResolve
        if dns is None or dns.status != 1:
            return

        for family, addr in dns.dns_res:
            print addr
            qq = s.query(DbHandshakeScanJob)\
                .filter(DbHandshakeScanJob.watch_id == watch.id)\
                .filter(DbHandshakeScanJob.ip_scanned == addr)
            tls = qq.order_by(DbHandshakeScanJob.last_scan_at.desc()).limit(1).first()  # type: DbHandshakeScanJob
            add_cache(s, tls)
    s.commit()


def whois(s):
    """
    Last whois scans
    :param s:
    :return:
    """
    doms = s.query(DbBaseDomain).all()
    for dom in doms:
        q = s.query(DbWhoisCheck).filter(DbWhoisCheck.domain_id == dom.id)
        whois = q.order_by(DbWhoisCheck.last_scan_at.desc()).limit(1).first()  # type: DbWhoisCheck
        add_cache(s, whois)
    s.commit()


def subs(s):
    """
    Subdomains scans
    :param s:
    :return:
    """
    subs = s.query(DbSubdomainWatchTarget).all()
    for sub in subs:
        q = s.query(DbSubdomainResultCache).filter(DbSubdomainResultCache.watch_id == sub.id)
        db_sub = q.order_by(DbSubdomainResultCache.last_scan_at.desc()).limit(1).first()  # type: DbSubdomainResultCache
        add_cache(s, db_sub)
    s.commit()


def upgrade():
    """
    Runs data migration methods
    :return:
    """
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = scoped_session(sessionmaker(bind=bind))

    flush_cache(sess)
    watch_based(sess)
    whois(sess)
    subs(sess)
    sess.commit()


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
