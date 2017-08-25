"""031 user accredit

Revision ID: 47ea77aa1d56
Revises: 587cf12b190e
Create Date: 2017-08-25 10:42:08.899649+00:00

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
revision = '47ea77aa1d56'
down_revision = '587cf12b190e'
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
    accredit = Column(String(100), default=None)
    accredit_own = Column(String(100), default=None)


def upgrade():
    op.add_column('users', sa.Column('accredit_own', sa.String(length=100), nullable=True))

    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = scoped_session(sessionmaker(bind=bind))

    q = sess.query(DbUser)
    for idx, cur in enumerate(DbHelper.yield_limit(q, DbUser.id)):  # type: DbUser
        try:
            m = hashlib.md5()
            cur.accredit_own = hashlib.md5('%s:%s' % (cur.id, cur.email)).hexdigest()[:24]

        except Exception as ex:
            logger.warning('Exception in DbWatchTarget is_ip_host migration: %s' % ex)
    sess.commit()


def downgrade():
    op.drop_column('users', 'accredit_own')


