"""003 data cert key data

Revision ID: 7260f851fc2e
Revises: 234951f144b3
Create Date: 2017-07-06 19:01:06.722847

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
import sys
from keychest import util
from keychest import util_cert
from keychest.consts import CertSigAlg

# revision identifiers, used by Alembic.
revision = '7260f851fc2e'
down_revision = '234951f144b3'
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

    id = Column(BigInteger, primary_key=True)
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
    pem = Column(Text, nullable=True)


#
# Data migration methods
#


def upgrade():
    # Data migration - online mode only
    if context.is_offline_mode():
        logger.warning('Data migration skipped in the offline mode')
        return

    bind = op.get_bind()
    sess = BaseSession(bind=bind)

    it = sess.query(Certificate).filter(Certificate.pem != None).yield_per(1000)
    for idx, cert_db in enumerate(it):  # type: Certificate
        try:
            cert = util.load_x509(cert_db.pem)  # type: cryptography.x509.Certificate
            alt_names = [util.utf8ize(x) for x in util.try_get_san(cert)]

            cname = util.utf8ize(util.try_get_cname(cert))
            subject = util.utf8ize(util.get_dn_string(cert.subject))
            issuer = util.utf8ize(util.get_dn_string(cert.issuer))

            cert_db.is_ca = util.try_is_ca(cert)
            cert_db.is_precert = util.try_is_precert(cert)
            cert_db.is_precert_ca = util.try_is_precert_ca(cert)
            cert_db.is_self_signed = util.try_is_self_signed(cert)
            cert_db.is_le = 'Let\'s Encrypt' in issuer

            alt_name_test = list(alt_names)
            if not util.is_empty(cname):
                alt_name_test.append(cname)

            cert_db.is_cloudflare = len(util_cert.cloudflare_altnames(alt_name_test)) > 0

            cert_db.sig_alg = CertSigAlg.oid_to_const(cert.signature_algorithm_oid)
            cert_db.key_type = util_cert.try_get_key_type(cert.public_key())
            cert_db.key_bit_size = util_cert.try_get_pubkey_size(cert.public_key())

        except Exception as ex:
            logger.warning('Exception in cert data migration: %s' % ex)

        if (idx % 100) == 0:
            # sess.commit()
            sys.stderr.write('.')
    sys.stderr.write('\n')
    sess.commit()


def downgrade():
    pass


