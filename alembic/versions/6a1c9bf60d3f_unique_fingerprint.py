"""unique fingerprint

Revision ID: 6a1c9bf60d3f
Revises: 8977a15fce13
Create Date: 2017-06-16 01:36:44.035385

"""
from alembic import op
from alembic import context
import logging

import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy import event, UniqueConstraint
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session as BaseSession, relationship


# revision identifiers, used by Alembic.
revision = '6a1c9bf60d3f'
down_revision = '8977a15fce13'
branch_labels = None
depends_on = None

Base = declarative_base()
logger = logging.getLogger(__name__)


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


def upgrade():
    remove_duplicates()

    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('certificates', 'fprint_sha1',
               existing_type=mysql.VARCHAR(length=40),
               nullable=False)
    op.create_unique_constraint('_fprint_sha1_uniqe', 'certificates', ['fprint_sha1'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('_fprint_sha1_uniqe', 'certificates', type_='unique')
    op.alter_column('certificates', 'fprint_sha1',
               existing_type=mysql.VARCHAR(length=40),
               nullable=True)
    # ### end Alembic commands ###


def remove_duplicates():
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
