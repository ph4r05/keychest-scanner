"""001 new scan system

Revision ID: 9a246a12d5e3
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
revision = '9a246a120000'
down_revision = None
branch_labels = None
depends_on = None

Base = declarative_base()
logger = logging.getLogger(__name__)


#
# Migration methods
#


def upgrade():
    pass



def downgrade():
    pass


