"""011 denormalized migration

Revision ID: 41339a2c71f7
Revises: b81169edac9e
Create Date: 2017-07-09 20:56:04.167414

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
from keychest.dbutil import DbHelper


# revision identifiers, used by Alembic.
revision = '41339a2c71f7'
down_revision = 'b81169edac9e'
branch_labels = None
depends_on = None


Base = declarative_base()
logger = logging.getLogger(__name__)


#
# Base classes for data migration
#


class DbWatchTarget(Base):
    __tablename__ = 'watch_target'
    id = Column(BigInteger, primary_key=True)
    scan_host = Column(String(255), nullable=False)
    scan_scheme = Column(String(255), nullable=True)
    scan_port = Column(String(255), nullable=True)
    last_dns_scan_id = Column(ForeignKey('scan_dns.id', name='wt_scan_dns_id', ondelete='SET NULL'),
                              nullable=True, index=True)


class DbDnsResolve(Base):
    __tablename__ = "scan_dns"
    id = Column(BigInteger, primary_key=True)
    watch_id = Column(ForeignKey('watch_target.id', name='dns_watch_target_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner
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
    __tablename__ = "scan_dns_entry"
    id = Column(BigInteger, primary_key=True)
    scan_id = Column(ForeignKey('scan_dns.id', name='scan_dns_entry_scan_id', ondelete='CASCADE'),
                     nullable=False, index=True)

    is_ipv6 = Column(SmallInteger, default=0, nullable=False)
    is_internal = Column(SmallInteger, default=0, nullable=False)
    ip = Column(String(191), nullable=False, index=True)
    res_order = Column(SmallInteger, default=0, nullable=False)


class DbHandshakeScanJob(Base):
    __tablename__ = 'scan_handshakes'
    id = Column(BigInteger, primary_key=True)

    job_id = Column(BigInteger, nullable=True)  # job id for web initiated scan
    watch_id = Column(ForeignKey('watch_target.id', name='tls_watch_target_id', ondelete='SET NULL'),
                      nullable=True, index=True)  # watch id scan for periodic scanner

    ip_scanned = Column(String(255), nullable=True)  # ip address used to connect to (remote peer IP)
    is_ipv6 = Column(SmallInteger, default=0, nullable=False)


#
# Data migration methods
#


def fixup_ipv6_col(s):
    """
    Recomputes is_ipv6 value for TLS scans
    :param s:
    :return:
    """
    it = s.query(DbHandshakeScanJob).filter(DbHandshakeScanJob.ip_scanned != None).yield_per(1000)
    for idx, cur in enumerate(it):  # type: DbHandshakeScanJob
        try:
            cur.is_ipv6 = TlsDomainTools.is_valid_ipv6_address(cur.ip_scanned)

        except Exception as ex:
            logger.warning('Exception in DbHandshakeScanJob is_ipv6 migration: %s' % ex)
    s.commit()


def migrate_dns_scan_fields(s):
    """
    Recomputes missing fields in the DNS record
    :param s:
    :return:
    """
    it = s.query(DbDnsResolve).filter(DbDnsResolve.status == 1).yield_per(1000)
    for idx, cur in enumerate(it):  # type: DbDnsResolve
        try:
            cur.num_scans = len(cur.dns_res)
            cur.num_ipv4 = len([x for x in cur.dns_res if x == 2])
            cur.num_ipv6 = len([x for x in cur.dns_res if x == 10])

        except Exception as ex:
            logger.warning('Exception in DbDnsResolve field migration: %s' % ex)
    s.commit()


def migrate_dns_entries(s):
    """
    Adds DNS scan entries
    :param s:
    :return:
    """
    # Delete all previous entries to simplify migration. This is corner case for dev server only.
    # On production the table will be created just second ago this migration script is run.
    s.query(DbDnsEntry).delete()
    s.commit()

    q = s.query(DbDnsResolve).filter(DbDnsResolve.status == 1)
    for idx, cur in enumerate(DbHelper.yield_limit(q, DbDnsResolve.id)):  # type: DbDnsResolve
        try:
            for idx, tup in enumerate(cur.dns_res):
                family, addr = tup
                entry = DbDnsEntry()
                entry.is_ipv6 = family == 10
                entry.is_internal = TlsDomainTools.is_ip_private(addr)
                entry.ip = addr
                entry.res_order = idx
                entry.scan_id = cur.id
                s.add(entry)
            s.flush()

        except Exception as ex:
            logger.warning('Exception in DbDnsResolve entry migration: %s' % ex)
    s.commit()


def migrate_last_dns_scan_id(s):
    """
    Locates the most recent DNS scan for all watch hosts.
    :param s:
    :return:
    """

    it = s.query(DbWatchTarget).yield_per(1000)
    for idx, cur in enumerate(it):  # type: DbWatchTarget
        q = s.query(DbDnsResolve).filter(DbDnsResolve.watch_id == cur.id)
        last_dns = q.order_by(DbDnsResolve.last_scan_at.desc()).limit(1).first()

        if last_dns is None:
            continue

        cur.last_dns_scan_id = last_dns.id
    s.commit()


#
# The logic
#


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

    # The migration
    fixup_ipv6_col(sess)
    migrate_dns_scan_fields(sess)
    migrate_dns_entries(sess)
    migrate_last_dns_scan_id(sess)


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
