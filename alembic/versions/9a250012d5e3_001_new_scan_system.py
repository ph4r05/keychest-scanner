"""001 new scan system

Revision ID: 9a250012d5e3
Revises: 
Create Date: 2017-06-29 20:55:33.109493

"""
from alembic import op
from alembic import context

import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy import event, UniqueConstraint
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session as BaseSession, relationship

import logging

# revision identifiers, used by Alembic.
revision = '9a250012d5e3'
down_revision = '9a246a120000'
branch_labels = None
depends_on = None

Base = declarative_base()
logger = logging.getLogger(__name__)


#
# Base classes for data migration
#

class Certificate(Base):
    """
    Certificate object
    """
    __tablename__ = 'certificates'
    __table_args__ = (UniqueConstraint('fprint_sha1', name='_fprint_sha1_uniqe'),)

    id = Column(BigInteger, primary_key=True)
    fprint_sha1 = Column(String(40), index=True, nullable=False)


class CertificateAltName(Base):
    __tablename__ = 'certificate_alt_names'
    cert_id = Column(BigInteger, index=True, primary_key=True)


class DbUser(Base):
    """
    Users - Laravel maintained table!
    Only columns needed for migration
    """
    __tablename__ = 'users'
    id = Column(INTEGER(10, unsigned=True), primary_key=True)


class DbWatchAssoc(Base):
    """
    User -> Watch target association.
    Only columns needed for migration (all in this case - new table), copied from dbutil.py
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


class DbWatchTarget(Base):
    """
    Watching target - scan server host. Only columns needed for migration
    """
    __tablename__ = 'watch_target'
    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, nullable=True)
    scan_host = Column(String(255), nullable=False)
    scan_scheme = Column(String(255), nullable=True)
    scan_port = Column(String(255), nullable=True)
    scan_periodicity = Column(BigInteger, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())


#
# Data migration methods
#

def remove_cert_fprint_duplicates():
    """
    Removes duplicate certificates - duplicate fingerprint
    :return:
    """
    # Data migration - online mode only
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = BaseSession(bind=bind)

    fprint_set = set()
    to_delete_set = set()

    it = sess.query(Certificate).yield_per(1000)
    for rec in it:   # type: Certificate
        if rec.fprint_sha1 is None:
            to_delete_set.add(rec.id)
            continue
        if rec.fprint_sha1 in fprint_set:
            to_delete_set.add(rec.id)
            continue
        fprint_set.add(rec.fprint_sha1)

    if len(to_delete_set) > 0:
        sess.query(Certificate).filter(Certificate.id.in_(list(to_delete_set)))\
            .delete(synchronize_session='fetch')
        sess.commit()

        sess.query(CertificateAltName).filter(CertificateAltName.cert_id.in_(list(to_delete_set)))\
            .delete(synchronize_session='fetch')
        sess.commit()
    sess.commit()


def migrate_watch_assoc():
    """
    Migrates watch targets to watch assocs
    :return:
    """
    # Data migration - online mode only
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    def strip(x):
        if x is None:
            return None
        return x.strip()

    def target_key(t):
        scheme, host, port = t.scan_scheme, t.scan_host, t.scan_port
        if scheme is None:
            scheme = 'https'
        if port is not None:
            port = int(port)
        if port is None:
            port = 443
        if scheme == 'http':
            scheme = 'https'
        if scheme == 'htttp':
            scheme = 'https'
        if port == 80 or port <= 10 or port >= 65535:
            port = 443
        host = strip(host)
        if host is not None:
            if host.startswith('*.'):
                host = host[2:]
            if host.startswith('%.'):
                host = host[2:]
        return scheme, host, port

    target_db = {}
    already_assoc = set()
    duplicates = []

    bind = op.get_bind()
    sess = BaseSession(bind=bind)
    it = sess.query(DbWatchTarget).yield_per(1000)
    for rec in it:
        ck = target_key(rec)
        rec_assoc = rec

        if ck in target_db:
            rec_assoc = target_db[ck]
            duplicates.append(rec.id)
        else:
            target_db[ck] = rec
            rec.scan_scheme = ck[0]
            rec.scan_host = ck[1]
            rec.scan_port = ck[2]

        if rec.user_id is None:
            continue

        cur_assoc_key = rec_assoc.id, rec.user_id
        if cur_assoc_key in already_assoc:
            print('already assoc: %s' % (cur_assoc_key,))
            continue
        already_assoc.add(cur_assoc_key)

        assoc = DbWatchAssoc()
        assoc.scan_type = 1
        assoc.created_at = rec_assoc.created_at
        assoc.updated_at = rec_assoc.updated_at
        assoc.scan_periodicity = rec_assoc.scan_periodicity
        assoc.user_id = rec.user_id  # actual record!
        assoc.watch_id = rec_assoc.id
        sess.add(assoc)
    sess.commit()

    # remove duplicates
    if len(duplicates) > 0:
        sess.query(DbWatchTarget).filter(DbWatchTarget.id.in_(list(duplicates))) \
            .delete(synchronize_session='fetch')
        sess.commit()
        print('Removed %s duplicates %s' % (len(duplicates), duplicates))


#
# Migration methods
#


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('base_domain',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('domain_name', sa.String(length=255), nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('domain_name')
                    )

    op.create_table('last_record_cache',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('record_key', sa.String(length=191), nullable=False),
                    sa.Column('record_at', sa.DateTime(), nullable=True),
                    sa.Column('record_id', sa.BigInteger(), nullable=True),
                    sa.Column('record_aux', sa.Text(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('record_key')
                    )

    op.create_table('system_last_events',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('event_key', sa.String(length=191), nullable=False),
                    sa.Column('event_at', sa.DateTime(), nullable=True),
                    sa.Column('aux', sa.Text(), nullable=True),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('event_key')
                    )

    op.create_table('whois_result',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('domain_id', sa.BigInteger(), nullable=False),
                    sa.Column('status', sa.SmallInteger(), nullable=True),
                    sa.Column('registrant_cc', sa.String(length=255), nullable=True),
                    sa.Column('registrar', sa.String(length=255), nullable=True),
                    sa.Column('registered_at', sa.DateTime(), nullable=True),
                    sa.Column('expires_at', sa.DateTime(), nullable=True),
                    sa.Column('dnssec', sa.SmallInteger(), nullable=True),
                    sa.Column('rec_updated_at', sa.DateTime(), nullable=True),
                    sa.Column('dns', sa.Text(), nullable=True),
                    sa.Column('emails', sa.Text(), nullable=True),
                    sa.Column('aux', sa.Text(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('last_scan_at', sa.DateTime(), nullable=True),
                    sa.Column('num_scans', sa.Integer(), nullable=True),
                    sa.ForeignKeyConstraint(['domain_id'], ['base_domain.id'], name='who_base_domain_id'),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_index(op.f('ix_whois_result_domain_id'), 'whois_result', ['domain_id'], unique=False)
    op.create_table('scan_dns',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('job_id', sa.BigInteger(), nullable=True),
                    sa.Column('watch_id', sa.BigInteger(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('last_scan_at', sa.DateTime(), nullable=True),
                    sa.Column('num_scans', sa.Integer(), nullable=True),
                    sa.Column('status', sa.SmallInteger(), nullable=True),
                    sa.Column('dns', sa.Text(), nullable=True),
                    sa.ForeignKeyConstraint(['watch_id'], ['watch_target.id'], name='dns_watch_target_id'),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_index(op.f('ix_scan_dns_watch_id'), 'scan_dns', ['watch_id'], unique=False)
    op.create_table('scan_gaps',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('watch_id', sa.BigInteger(), nullable=True),
                    sa.Column('scan_code', sa.SmallInteger(), nullable=False),
                    sa.Column('scan_type', sa.SmallInteger(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('gap_start', sa.DateTime(), nullable=True),
                    sa.Column('gap_end', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['watch_id'], ['watch_target.id'], name='sgap_watch_target_id'),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_index(op.f('ix_scan_gaps_watch_id'), 'scan_gaps', ['watch_id'], unique=False)

    op.create_table('scan_history',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('watch_id', sa.BigInteger(), nullable=True),
                    sa.Column('scan_code', sa.SmallInteger(), nullable=False),
                    sa.Column('scan_type', sa.SmallInteger(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['watch_id'], ['watch_target.id'], name='shist_watch_target_id'),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_index(op.f('ix_scan_history_watch_id'), 'scan_history', ['watch_id'], unique=False)

    op.create_table('user_watch_target',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('user_id', mysql.INTEGER(display_width=10, unsigned=True), nullable=False),
                    sa.Column('watch_id', sa.BigInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('deleted_at', sa.DateTime(), nullable=True),
                    sa.Column('scan_periodicity', sa.BigInteger(), nullable=True),
                    sa.Column('scan_type', sa.Integer(), nullable=True),
                    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='wa_users_id'),
                    sa.ForeignKeyConstraint(['watch_id'], ['watch_target.id'], name='wa_watch_target_id'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('user_id', 'watch_id', name='wa_user_watcher_uniqe')
                    )
    op.create_index(op.f('ix_user_watch_target_user_id'), 'user_watch_target', ['user_id'], unique=False)
    op.create_index(op.f('ix_user_watch_target_watch_id'), 'user_watch_target', ['watch_id'], unique=False)

    op.alter_column(u'certificates', 'fprint_sha1',
                    existing_type=mysql.VARCHAR(length=40),
                    nullable=False)
    op.alter_column(u'certificates', 'is_precert',
                    existing_type=mysql.SMALLINT(display_width=6),
                    nullable=False,
                    existing_server_default=sa.text(u"'0'"))
    op.alter_column(u'certificates', 'is_precert_ca',
                    existing_type=mysql.SMALLINT(display_width=6),
                    nullable=False,
                    existing_server_default=sa.text(u"'0'"))

    # removing duplicate fprints
    remove_cert_fprint_duplicates()
    op.create_unique_constraint('crt_fprint_sha1_uniqe', 'certificates', ['fprint_sha1'])

    op.add_column(u'crtsh_query', sa.Column('last_scan_at', sa.DateTime(), nullable=True))
    op.add_column(u'crtsh_query', sa.Column('num_scans', sa.Integer(), nullable=True))
    op.add_column(u'crtsh_query', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.add_column(u'crtsh_query', sa.Column('watch_id', sa.BigInteger(), nullable=True))

    op.create_index(op.f('ix_crtsh_query_watch_id'), 'crtsh_query', ['watch_id'], unique=False)
    op.create_foreign_key('crtsh_watch_target_id', 'crtsh_query', 'watch_target', ['watch_id'], ['id'])

    op.add_column(u'scan_handshakes', sa.Column('last_scan_at', sa.DateTime(), nullable=True))
    op.add_column(u'scan_handshakes', sa.Column('num_scans', sa.Integer(), nullable=True))
    op.add_column(u'scan_handshakes', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.add_column(u'scan_handshakes', sa.Column('watch_id', sa.BigInteger(), nullable=True))

    op.create_index(op.f('ix_scan_handshakes_watch_id'), 'scan_handshakes', ['watch_id'], unique=False)
    op.create_foreign_key('tls_watch_target_id', 'scan_handshakes', 'watch_target', ['watch_id'], ['id'])

    op.add_column(u'scan_jobs', sa.Column('crtsh_check_id', sa.BigInteger(), nullable=True))
    op.add_column(u'scan_jobs', sa.Column('crtsh_checks', sa.String(length=255), nullable=True))
    op.add_column(u'scan_jobs', sa.Column('dns_check_id', sa.BigInteger(), nullable=True))
    op.add_column(u'scan_jobs', sa.Column('whois_check_id', sa.BigInteger(), nullable=True))
    op.alter_column(u'scan_jobs', 'scan_host',
                    existing_type=mysql.VARCHAR(collation=u'utf8mb4_unicode_ci', length=191),
                    nullable=True)

    op.create_index(op.f('ix_scan_jobs_crtsh_check_id'), 'scan_jobs', ['crtsh_check_id'], unique=False)
    op.create_index(op.f('ix_scan_jobs_dns_check_id'), 'scan_jobs', ['dns_check_id'], unique=False)
    op.create_index(op.f('ix_scan_jobs_whois_check_id'), 'scan_jobs', ['whois_check_id'], unique=False)

    op.create_foreign_key('sjob_whois_result_id', 'scan_jobs', 'whois_result', ['whois_check_id'], ['id'])
    op.create_foreign_key('sjob_crtsh_query_id', 'scan_jobs', 'crtsh_query', ['crtsh_check_id'], ['id'])
    op.create_foreign_key('sjob_scan_dns_id', 'scan_jobs', 'scan_dns', ['dns_check_id'], ['id'])

    op.add_column(u'watch_target', sa.Column('last_scan_state', sa.SmallInteger(), nullable=True))
    op.add_column(u'watch_target', sa.Column('top_domain_id', sa.BigInteger(), nullable=True))

    op.create_index(op.f('ix_watch_target_top_domain_id'), 'watch_target', ['top_domain_id'], unique=False)
    op.create_foreign_key('wt_base_domain_id', 'watch_target', 'base_domain', ['top_domain_id'], ['id'])

    # watch assoc migration
    migrate_watch_assoc()

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('wt_base_domain_id', 'watch_target', type_='foreignkey')
    op.drop_index(op.f('ix_watch_target_top_domain_id'), table_name='watch_target')
    op.drop_column(u'watch_target', 'top_domain_id')
    op.drop_column(u'watch_target', 'last_scan_state')
    op.drop_constraint('sjob_scan_dns_id', 'scan_jobs', type_='foreignkey')
    op.drop_constraint('sjob_crtsh_query_id', 'scan_jobs', type_='foreignkey')
    op.drop_constraint('sjob_whois_result_id', 'scan_jobs', type_='foreignkey')
    op.drop_constraint('wa_users_id', 'user_watch_target', type_='foreignkey')
    op.drop_constraint('wa_watch_target_id', 'user_watch_target', type_='foreignkey')
    op.drop_constraint('shist_watch_target_id', 'scan_history', type_='foreignkey')
    op.drop_constraint('sgap_watch_target_id', 'scan_gaps', type_='foreignkey')
    op.drop_constraint('dns_watch_target_id', 'scan_dns', type_='foreignkey')
    op.drop_constraint('who_base_domain_id', 'whois_result', type_='foreignkey')
    op.drop_index(op.f('ix_scan_jobs_whois_check_id'), table_name='scan_jobs')
    op.drop_index(op.f('ix_scan_jobs_dns_check_id'), table_name='scan_jobs')
    op.drop_index(op.f('ix_scan_jobs_crtsh_check_id'), table_name='scan_jobs')
    op.alter_column(u'scan_jobs', 'scan_host',
                    existing_type=mysql.VARCHAR(collation=u'utf8mb4_unicode_ci', length=191),
                    nullable=False)
    op.drop_column(u'scan_jobs', 'whois_check_id')
    op.drop_column(u'scan_jobs', 'dns_check_id')
    op.drop_column(u'scan_jobs', 'crtsh_checks')
    op.drop_column(u'scan_jobs', 'crtsh_check_id')
    op.drop_constraint('tls_watch_target_id', 'scan_handshakes', type_='foreignkey')
    op.drop_index(op.f('ix_scan_handshakes_watch_id'), table_name='scan_handshakes')
    op.drop_column(u'scan_handshakes', 'watch_id')
    op.drop_column(u'scan_handshakes', 'updated_at')
    op.drop_column(u'scan_handshakes', 'num_scans')
    op.drop_column(u'scan_handshakes', 'last_scan_at')
    op.drop_constraint('crtsh_watch_target_id', 'crtsh_query', type_='foreignkey')
    op.drop_index(op.f('ix_crtsh_query_watch_id'), table_name='crtsh_query')
    op.drop_column(u'crtsh_query', 'watch_id')
    op.drop_column(u'crtsh_query', 'updated_at')
    op.drop_column(u'crtsh_query', 'num_scans')
    op.drop_column(u'crtsh_query', 'last_scan_at')
    op.drop_constraint('crt_fprint_sha1_uniqe', 'certificates', type_='unique')
    op.alter_column(u'certificates', 'is_precert_ca',
                    existing_type=mysql.SMALLINT(display_width=6),
                    nullable=True,
                    existing_server_default=sa.text(u"'0'"))
    op.alter_column(u'certificates', 'is_precert',
                    existing_type=mysql.SMALLINT(display_width=6),
                    nullable=True,
                    existing_server_default=sa.text(u"'0'"))
    op.alter_column(u'certificates', 'fprint_sha1',
                    existing_type=mysql.VARCHAR(length=40),
                    nullable=True)
    op.drop_index(op.f('ix_user_watch_target_watch_id'), table_name='user_watch_target')
    op.drop_index(op.f('ix_user_watch_target_user_id'), table_name='user_watch_target')
    op.drop_table('user_watch_target')
    op.drop_index(op.f('ix_scan_history_watch_id'), table_name='scan_history')
    op.drop_table('scan_history')
    op.drop_index(op.f('ix_scan_gaps_watch_id'), table_name='scan_gaps')
    op.drop_table('scan_gaps')
    op.drop_index(op.f('ix_scan_dns_watch_id'), table_name='scan_dns')
    op.drop_table('scan_dns')
    op.drop_index(op.f('ix_whois_result_domain_id'), table_name='whois_result')
    op.drop_table('whois_result')
    op.drop_table('system_last_events')
    op.drop_table('last_record_cache')
    op.drop_table('base_domain')
    # ### end Alembic commands ###
