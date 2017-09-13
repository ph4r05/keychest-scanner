"""035 user fields extended

Revision ID: 9780d115b745
Revises: ca810efb8135
Create Date: 2017-09-13 15:46:55.770680+00:00

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
import hashlib
from keychest import util
from keychest.dbutil import DbHelper, ResultModelUpdater


# revision identifiers, used by Alembic.
revision = '9780d115b745'
down_revision = 'ca810efb8135'
branch_labels = None
depends_on = None


Base = declarative_base()
logger = logging.getLogger(__name__)


class DbUser(Base):
    """
    Users - Laravel maintained table!
    """
    __tablename__ = 'users'
    id = Column(INTEGER(10, unsigned=True), primary_key=True)
    name = Column(String(191), nullable=False)
    email = Column(String(191), nullable=False, unique=True)

    email_verify_token = Column(String(40), nullable=True)
    notification_email = Column(String(191), nullable=True)
    weekly_unsubscribe_token = Column(String(40), nullable=True)

    cert_notif_state = Column(SmallInteger, nullable=False, default=0)
    cert_notif_unsubscribe_token = Column(String(24), nullable=True)
    cert_notif_last_cert_id = Column(BigInteger, default=None, nullable=True)
    last_email_cert_notif_sent_at = Column(DateTime, default=None)
    last_email_cert_notif_enqueued_at = Column(DateTime, default=None)


def upgrade():
    """
    Upgrade
    :return:
    """
    op.add_column('users', sa.Column('closed_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('deleted_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('email_verify_token', sa.String(length=24), nullable=True))
    op.add_column('users', sa.Column('email_verified_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('notification_email', sa.String(length=191), nullable=True))
    op.add_column('users', sa.Column('weekly_unsubscribe_token', sa.String(length=24), nullable=True))

    op.add_column('users', sa.Column('cert_notif_state', sa.SmallInteger(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('cert_notif_unsubscribe_token', sa.String(length=24), nullable=True))
    op.add_column('users', sa.Column('cert_notif_last_cert_id', sa.BigInteger(), nullable=True))
    op.add_column('users', sa.Column('last_email_cert_notif_sent_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('last_email_cert_notif_enqueued_at', sa.DateTime(), nullable=True))

    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = scoped_session(sessionmaker(bind=bind))

    q = sess.query(DbUser)
    for idx, cur in enumerate(DbHelper.yield_limit(q, DbUser.id)):  # type: DbUser
        try:
            cur.email_verify_token = util.random_alphanum(24)
            cur.weekly_unsubscribe_token = util.random_alphanum(24)
            cur.cert_notif_unsubscribe_token = util.random_alphanum(24)

        except Exception as ex:
            logger.warning('Exception in User field migration: %s' % ex)
    sess.commit()


def downgrade():
    """
    Downgrade
    :return:
    """
    op.drop_column('users', 'last_email_cert_notif_enqueued_at')
    op.drop_column('users', 'last_email_cert_notif_sent_at')
    op.drop_column('users', 'cert_notif_last_cert_id')
    op.drop_column('users', 'cert_notif_unsubscribe_token')
    op.drop_column('users', 'cert_notif_state')
    op.drop_column('users', 'weekly_unsubscribe_token')
    op.drop_column('users', 'notification_email')
    op.drop_column('users', 'email_verify_token')
    op.drop_column('users', 'email_verified_at')
    op.drop_column('users', 'deleted_at')
    op.drop_column('users', 'closed_at')


