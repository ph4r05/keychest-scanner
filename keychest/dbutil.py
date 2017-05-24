#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import util
import errors
import logging

from sqlalchemy import create_engine
from sqlalchemy import exc as sa_exc
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
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

    fprint_sha1 = Column(String(40), index=True, nullable=True)
    fprint_sha256 = Column(String(64), index=True, nullable=True)

    valid_from = Column(DateTime, default=None, nullable=True)
    valid_to = Column(DateTime, default=None, nullable=True)

    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=func.now())

    cname = Column(Text, nullable=True)
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True)
    pem = Column(Text, nullable=True)

    source = Column(String(255), nullable=True)  # CT / crt.sh / manual


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

