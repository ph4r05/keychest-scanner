"""046 ownership overhaul

Revision ID: f7dcd0d26e39
Revises: 9735dbbb86c7
Create Date: 2017-11-24 14:24:18.685893+00:00

"""
from alembic import op
from alembic import context

import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy import event, UniqueConstraint
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session as BaseSession

import logging

# revision identifiers, used by Alembic.
from keychest.dbutil import DbHelper

revision = 'f7dcd0d26e39'
down_revision = '9735dbbb86c7'
branch_labels = None
depends_on = None

Base = declarative_base()
logger = logging.getLogger(__name__)


#
# Base classes for data migration
#


class DbUser(Base):
    """
    Users - Laravel maintained table!
    Only columns needed for migration
    """
    __tablename__ = 'users'
    id = Column(INTEGER(10, unsigned=True), primary_key=True)
    email = Column(String(191), nullable=False)
    primary_owner_id = Column(ForeignKey('owners.id', name='fk_users_primary_owner_id', ondelete='SET NULL'),
                              nullable=True, index=True)


class DbOwner(Base):
    """
    Abstract owner record for resource ownership management
    """
    __tablename__ = "owners"
    id = Column(BigInteger, primary_key=True)
    name = Column(String(191), nullable=False)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


class DbUserToOwner(Base):
    """
    User -> Owner mapping
    """
    __tablename__ = "user_to_owner"
    __table_args__ = (UniqueConstraint('user_id', 'owner_id', name='uk_user_to_owner_user_owner'),)
    id = Column(BigInteger, primary_key=True)

    user_id = Column(ForeignKey('users.id', name='fk_user_to_owner_user_id', ondelete='CASCADE'),
                     nullable=False, index=True)
    owner_id = Column(ForeignKey('owners.id', name='fk_user_to_owner_owner_id', ondelete='CASCADE'),
                      nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())


#
# Association tables
#


class DbKeychestAgent(Base):
    """
    Keychest agent record - identifies particular keychest slave instance
    """
    __tablename__ = 'keychest_agent'
    id = Column(BigInteger, primary_key=True)


class DbWatchTarget(Base):
    """
    Watching target - scan server host.
    Watch target is immutable w.r.t (scan_host, scan_scheme, scan_port)
     i.e., it has always the same ID for the results consistency.
    """
    __tablename__ = 'watch_target'
    id = Column(BigInteger, primary_key=True)


class DbWatchAssocUsers(Base):
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


class DbWatchAssoc(Base):
    """
    Owner -> Watch target association
    Enables to have watch_target id immutable to have valid results with target_id.
    Also helps with deduplication of watch target scans.
    """
    __tablename__ = 'owner_watch_target'
    __table_args__ = (UniqueConstraint('owner_id', 'watch_id', name='uk_owner_watch_target_owner_watch'),)
    id = Column(BigInteger, primary_key=True)

    owner_id = Column(ForeignKey('owners.id', name='fk_owner_watch_target_owner_id',
                                 ondelete='CASCADE'), nullable=False, index=True)
    watch_id = Column(ForeignKey('watch_target.id', name='fk_owner_watch_target_watch_id', ondelete='CASCADE'),
                      nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    deleted_at = Column(DateTime, default=None, nullable=True)
    disabled_at = Column(DateTime, default=None, nullable=True)  # user disables this entry
    auto_scan_added_at = Column(DateTime, default=None, nullable=True)  # date of the auto-detection added this entry

    scan_periodicity = Column(BigInteger, nullable=True)
    scan_type = Column(Integer, nullable=True)


class DbSubdomainWatchTarget(Base):
    """
    Watching target for subdomain auto-detection.
    """
    __tablename__ = 'subdomain_watch_target'
    id = Column(BigInteger, primary_key=True)


class DbSubdomainWatchAssocUsers(Base):
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


class DbSubdomainWatchAssoc(Base):
    """
    Owner -> subdomain Watch target association
    Enables to have watch_target id immutable to have valid results with target_id.
    Also helps with deduplication of watch target scans.
    """
    __tablename__ = 'owner_subdomain_watch_target'
    __table_args__ = (UniqueConstraint('owner_id', 'watch_id', name='uk_owner_subdomain_watch_target_owner_watch'),)
    id = Column(BigInteger, primary_key=True)

    owner_id = Column(ForeignKey('owners.id', name='fk_owner_subdomain_watch_target_owner_id',
                                 ondelete='CASCADE'), nullable=False, index=True)
    watch_id = Column(ForeignKey('subdomain_watch_target.id', name='fk_owner_subdomain_watch_target_watch_id', ondelete='CASCADE'),
                      nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    deleted_at = Column(DateTime, default=None, nullable=True)
    disabled_at = Column(DateTime, default=None, nullable=True)
    auto_scan_added_at = Column(DateTime, default=None, nullable=True)

    scan_periodicity = Column(BigInteger, nullable=True)
    scan_type = Column(Integer, nullable=True)
    auto_fill_watches = Column(SmallInteger, default=0, nullable=False)  # if 1 new hosts will be converted to active watches


class DbIpScanRecord(Base):
    """
    IP scanning record.
    Scans the IPv4 range and looks for the servers
    """
    __tablename__ = 'ip_scan_record'
    id = Column(BigInteger, primary_key=True)


class DbIpScanRecordUserUser(Base):
    """
    User -> IpScanRecord target association
    Enables to have watch_target id immutable to have valid results with target_id.
    Also helps with deduplication of watch target scans.
    """
    __tablename__ = 'user_ip_scan_record'
    __table_args__ = (UniqueConstraint('user_id', 'ip_scan_record_id', name='uk_user_ip_scan_record_unique'),)
    id = Column(BigInteger, primary_key=True)

    user_id = Column(ForeignKey('users.id', name='fk_user_ip_scan_record_users_id', ondelete='CASCADE'),
                     nullable=False, index=True)
    ip_scan_record_id = Column(ForeignKey('ip_scan_record.id', name='fk_ip_scan_record_ip_scan_record_id',
                                          ondelete='CASCADE'), nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    deleted_at = Column(DateTime, default=None, nullable=True)
    disabled_at = Column(DateTime, default=None, nullable=True)  # user disables this entry

    scan_periodicity = Column(BigInteger, nullable=True)
    auto_fill_watches = Column(SmallInteger, default=0, nullable=False) # if 1 new hosts will be converted to active watches


class DbIpScanRecordUser(Base):
    """
    Owner -> IpScanRecord target association
    Enables to have watch_target id immutable to have valid results with target_id.
    Also helps with deduplication of watch target scans.
    """
    __tablename__ = 'owner_ip_scan_record'
    __table_args__ = (UniqueConstraint('owner_id', 'ip_scan_record_id', name='uk_owner_ip_scan_record_unique'),)
    id = Column(BigInteger, primary_key=True)

    owner_id = Column(ForeignKey('owners.id', name='fk_owner_ip_scan_record_owner_id',
                                 ondelete='CASCADE'), nullable=False, index=True)
    ip_scan_record_id = Column(ForeignKey('ip_scan_record.id', name='fk_owner_ip_scan_record_ip_scan_record_id',
                                          ondelete='CASCADE'), nullable=False, index=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())
    deleted_at = Column(DateTime, default=None, nullable=True)
    disabled_at = Column(DateTime, default=None, nullable=True)  # user disables this entry

    scan_periodicity = Column(BigInteger, nullable=True)
    auto_fill_watches = Column(SmallInteger, default=0, nullable=False) # if 1 new hosts will be converted to active watches


#
# Migration
#


def clean_agents():
    """
    Agents cleanup
    :return:
    """
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = BaseSession(bind=bind)

    sess.query(DbKeychestAgent) \
        .delete(synchronize_session='fetch')
    sess.commit()


def create_owners():
    """
    Create 1:1 user owners, with the same primary key for easy transition
    :return:
    """
    # Data migration - online mode only
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = BaseSession(bind=bind)

    q = sess.query(DbUser)
    it = DbHelper.yield_limit(q, DbUser.id)
    for rec in it:   # type: DbUser
        own = DbOwner()
        own.id = rec.id
        own.name = rec.email
        own.created_at = sa.func.now()
        own.updated_at = sa.func.now()
        sess.add(own)

        uown = DbUserToOwner()
        uown.user_id = rec.id
        uown.owner_id = own.id
        uown.created_at = sa.func.now()
        uown.updated_at = sa.func.now()

        rec.primary_owner_id = own.id
        sess.flush()
    sess.commit()


def migrate_watch_assoc():
    """
    Migrate watch assoc to owners
    :return:
    """
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = BaseSession(bind=bind)

    q = sess.query(DbWatchAssocUsers)
    it = DbHelper.yield_limit(q, DbWatchAssocUsers.id)
    for rec in it:  # type: DbWatchAssocUsers
        model_rep = DbHelper.to_dict(rec)
        model_rep['owner_id'] = model_rep.pop('user_id', None)

        new_model = DbHelper.to_model(obj=model_rep, ret=DbWatchAssoc())
        sess.add(new_model)

    sess.commit()


def migrate_subdomain_watch_assoc():
    """
    Migrate subdomain watch assoc to owners
    :return:
    """
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = BaseSession(bind=bind)

    q = sess.query(DbSubdomainWatchAssocUsers)
    it = DbHelper.yield_limit(q, DbSubdomainWatchAssocUsers.id)
    for rec in it:  # type: DbSubdomainWatchAssocUsers
        model_rep = DbHelper.to_dict(rec)
        model_rep['owner_id'] = model_rep.pop('user_id', None)

        new_model = DbHelper.to_model(obj=model_rep, ret=DbSubdomainWatchAssoc())
        sess.add(new_model)

    sess.commit()


def migrate_ipscan_watch_assoc():
    """
    Migrate ipscan watch assoc to owners
    :return:
    """
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = BaseSession(bind=bind)

    q = sess.query(DbIpScanRecordUserUser)
    it = DbHelper.yield_limit(q, DbIpScanRecordUserUser.id)
    for rec in it:  # type: DbIpScanRecordUserUser
        model_rep = DbHelper.to_dict(rec)
        model_rep['owner_id'] = model_rep.pop('user_id', None)

        new_model = DbHelper.to_model(obj=model_rep, ret=DbIpScanRecordUser())
        sess.add(new_model)

    sess.commit()


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('owners',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('name', sa.String(length=191), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_table('owner_ip_scan_record',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('owner_id', sa.BigInteger(), nullable=False),
                    sa.Column('ip_scan_record_id', sa.BigInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('deleted_at', sa.DateTime(), nullable=True),
                    sa.Column('disabled_at', sa.DateTime(), nullable=True),
                    sa.Column('scan_periodicity', sa.BigInteger(), nullable=True),
                    sa.Column('auto_fill_watches', sa.SmallInteger(), nullable=False),
                    sa.ForeignKeyConstraint(['ip_scan_record_id'], ['ip_scan_record.id'],
                                            name='fk_owner_ip_scan_record_ip_scan_record_id', ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['owner_id'], ['owners.id'], name='fk_owner_ip_scan_record_owner_id',
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('owner_id', 'ip_scan_record_id', name='uk_owner_ip_scan_record_unique')
                    )
    op.create_index(op.f('ix_owner_ip_scan_record_ip_scan_record_id'), 'owner_ip_scan_record', ['ip_scan_record_id'],
                    unique=False)
    op.create_index(op.f('ix_owner_ip_scan_record_owner_id'), 'owner_ip_scan_record', ['owner_id'], unique=False)

    op.create_table('owner_subdomain_watch_target',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('owner_id', sa.BigInteger(), nullable=False),
                    sa.Column('watch_id', sa.BigInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('deleted_at', sa.DateTime(), nullable=True),
                    sa.Column('disabled_at', sa.DateTime(), nullable=True),
                    sa.Column('auto_scan_added_at', sa.DateTime(), nullable=True),
                    sa.Column('scan_periodicity', sa.BigInteger(), nullable=True),
                    sa.Column('scan_type', sa.Integer(), nullable=True),
                    sa.Column('auto_fill_watches', sa.SmallInteger(), nullable=False),
                    sa.ForeignKeyConstraint(['owner_id'], ['owners.id'],
                                            name='fk_owner_subdomain_watch_target_owner_id', ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['watch_id'], ['subdomain_watch_target.id'],
                                            name='fk_owner_subdomain_watch_target_watch_id', ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('owner_id', 'watch_id', name='uk_owner_subdomain_watch_target_owner_watch')
                    )
    op.create_index(op.f('ix_owner_subdomain_watch_target_owner_id'), 'owner_subdomain_watch_target', ['owner_id'],
                    unique=False)
    op.create_index(op.f('ix_owner_subdomain_watch_target_watch_id'), 'owner_subdomain_watch_target', ['watch_id'],
                    unique=False)

    op.create_table('owner_watch_target',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('owner_id', sa.BigInteger(), nullable=False),
                    sa.Column('watch_id', sa.BigInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('deleted_at', sa.DateTime(), nullable=True),
                    sa.Column('disabled_at', sa.DateTime(), nullable=True),
                    sa.Column('auto_scan_added_at', sa.DateTime(), nullable=True),
                    sa.Column('scan_periodicity', sa.BigInteger(), nullable=True),
                    sa.Column('scan_type', sa.Integer(), nullable=True),
                    sa.ForeignKeyConstraint(['owner_id'], ['owners.id'], name='fk_owner_watch_target_owner_id',
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['watch_id'], ['watch_target.id'], name='fk_owner_watch_target_watch_id',
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('owner_id', 'watch_id', name='uk_owner_watch_target_owner_watch')
                    )
    op.create_index(op.f('ix_owner_watch_target_owner_id'), 'owner_watch_target', ['owner_id'], unique=False)
    op.create_index(op.f('ix_owner_watch_target_watch_id'), 'owner_watch_target', ['watch_id'], unique=False)

    op.create_table('user_to_owner',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('user_id', mysql.INTEGER(display_width=10, unsigned=True), nullable=False),
                    sa.Column('owner_id', sa.BigInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['owner_id'], ['owners.id'], name='fk_user_to_owner_owner_id',
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_user_to_owner_user_id',
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('user_id', 'owner_id', name='uk_user_to_owner_user_owner')
                    )
    op.create_index(op.f('ix_user_to_owner_owner_id'), 'user_to_owner', ['owner_id'], unique=False)
    op.create_index(op.f('ix_user_to_owner_user_id'), 'user_to_owner', ['user_id'], unique=False)

    # Agents have to be removed before not null
    clean_agents()

    op.add_column(u'keychest_agent', sa.Column('owner_id', sa.BigInteger(), nullable=False))
    op.create_index(op.f('ix_keychest_agent_owner_id'), 'keychest_agent', ['owner_id'], unique=False)
    op.create_foreign_key('fk_keychest_agent_owner_id', 'keychest_agent', 'owners', ['owner_id'], ['id'],
                          ondelete='CASCADE')

    op.add_column(u'managed_host_groups', sa.Column('owner_id', sa.BigInteger(), nullable=True))
    op.create_index(op.f('ix_managed_host_groups_owner_id'), 'managed_host_groups', ['owner_id'], unique=False)
    op.drop_constraint(u'managed_host_groups_users_id', 'managed_host_groups', type_='foreignkey')
    op.drop_index('ix_managed_host_groups_user_id', table_name='managed_host_groups')
    op.create_foreign_key('managed_host_groups_owner_id', 'managed_host_groups', 'owners', ['owner_id'], ['id'],
                          ondelete='CASCADE')
    op.drop_column(u'managed_host_groups', 'user_id')

    op.add_column(u'managed_hosts', sa.Column('owner_id', sa.BigInteger(), nullable=True))
    op.create_index(op.f('ix_managed_hosts_owner_id'), 'managed_hosts', ['owner_id'], unique=False)
    op.drop_constraint(u'uk_managed_hosts_host_uk', 'managed_hosts', type_='unique')
    op.create_unique_constraint('uk_managed_hosts_host_uk', 'managed_hosts',
                                ['host_addr', 'ssh_port', 'owner_id', 'agent_id'])

    op.drop_constraint(u'managed_hosts_users_id', 'managed_hosts', type_='foreignkey')
    op.drop_index('ix_managed_hosts_user_id', table_name='managed_hosts')
    op.create_foreign_key('managed_hosts_owner_id', 'managed_hosts', 'owners', ['owner_id'], ['id'], ondelete='CASCADE')
    op.drop_column(u'managed_hosts', 'user_id')

    op.add_column(u'ssh_keys', sa.Column('owner_id', sa.BigInteger(), nullable=True))
    op.create_index(op.f('ix_ssh_keys_owner_id'), 'ssh_keys', ['owner_id'], unique=False)
    op.create_foreign_key('ssh_keys_owner_id', 'ssh_keys', 'owners', ['owner_id'], ['id'], ondelete='CASCADE')

    op.add_column(u'users', sa.Column('primary_owner_id', sa.BigInteger(), nullable=True))
    op.create_index(op.f('ix_users_primary_owner_id'), 'users', ['primary_owner_id'], unique=False)
    op.create_foreign_key('fk_users_primary_owner_id', 'users', 'owners', ['primary_owner_id'], ['id'],
                          ondelete='SET NULL')

    #
    # Data migration
    #

    create_owners()
    migrate_watch_assoc()
    migrate_subdomain_watch_assoc()
    migrate_ipscan_watch_assoc()


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('fk_users_primary_owner_id', 'users', type_='foreignkey')
    op.drop_index(op.f('ix_users_primary_owner_id'), table_name='users')
    op.drop_column(u'users', 'primary_owner_id')

    op.drop_constraint('ssh_keys_owner_id', 'ssh_keys', type_='foreignkey')
    op.drop_index(op.f('ix_ssh_keys_owner_id'), table_name='ssh_keys')
    op.drop_column(u'ssh_keys', 'owner_id')

    op.add_column(u'managed_hosts',
                  sa.Column('user_id', mysql.INTEGER(display_width=10, unsigned=True), autoincrement=False,
                            nullable=False))
    op.drop_constraint('managed_hosts_owner_id', 'managed_hosts', type_='foreignkey')

    op.drop_constraint('uk_managed_hosts_host_uk', 'managed_hosts', type_='unique')
    op.drop_index(op.f('ix_managed_hosts_owner_id'), table_name='managed_hosts')

    op.create_unique_constraint(u'uk_managed_hosts_host_uk', 'managed_hosts',
                                ['host_addr', 'ssh_port', 'user_id', 'agent_id'])
    op.create_index('ix_managed_hosts_user_id', 'managed_hosts', ['user_id'], unique=False)
    op.create_foreign_key(u'managed_hosts_users_id', 'managed_hosts', 'users', ['user_id'], ['id'], ondelete=u'CASCADE')

    op.drop_column(u'managed_hosts', 'owner_id')
    op.add_column(u'managed_host_groups',
                  sa.Column('user_id', mysql.INTEGER(display_width=10, unsigned=True), autoincrement=False,
                            nullable=False))
    op.drop_constraint('managed_host_groups_owner_id', 'managed_host_groups', type_='foreignkey')

    op.create_index('ix_managed_host_groups_user_id', 'managed_host_groups', ['user_id'], unique=False)
    op.create_foreign_key(u'managed_host_groups_users_id', 'managed_host_groups', 'users', ['user_id'], ['id'],
                          ondelete=u'CASCADE')

    op.drop_index(op.f('ix_managed_host_groups_owner_id'), table_name='managed_host_groups')
    op.drop_column(u'managed_host_groups', 'owner_id')
    op.drop_constraint('fk_keychest_agent_owner_id', 'keychest_agent', type_='foreignkey')
    op.drop_index(op.f('ix_keychest_agent_owner_id'), table_name='keychest_agent')
    op.drop_column(u'keychest_agent', 'owner_id')

    # op.drop_index(op.f('ix_user_to_owner_user_id'), table_name='user_to_owner')
    # op.drop_index(op.f('ix_user_to_owner_owner_id'), table_name='user_to_owner')
    op.drop_table('user_to_owner')
    # op.drop_index(op.f('ix_owner_watch_target_watch_id'), table_name='owner_watch_target')
    # op.drop_index(op.f('ix_owner_watch_target_owner_id'), table_name='owner_watch_target')
    op.drop_table('owner_watch_target')
    # op.drop_index(op.f('ix_owner_subdomain_watch_target_watch_id'), table_name='owner_subdomain_watch_target')
    # op.drop_index(op.f('ix_owner_subdomain_watch_target_owner_id'), table_name='owner_subdomain_watch_target')
    op.drop_table('owner_subdomain_watch_target')
    # op.drop_index(op.f('ix_owner_ip_scan_record_owner_id'), table_name='owner_ip_scan_record')
    # op.drop_index(op.f('ix_owner_ip_scan_record_ip_scan_record_id'), table_name='owner_ip_scan_record')
    op.drop_table('owner_ip_scan_record')
    op.drop_table('owners')
    # ### end Alembic commands ###
