#!/usr/bin/env python
# -*- coding: utf-8 -*-

import util
import dbutil
from dbutil import AlembicDataMigration
import base64
import logging
from trace_logger import Tracelogger


logger = logging.getLogger(__name__)


# current data migration version, integer
CUR_VERSION = 2


class DbMigrationManager(object):
    """
    On the fly data migrations.
    """
    def __init__(self, s=None, should_terminate=None):
        self.should_terminate = should_terminate
        self.s = s
        self.trace_logger = Tracelogger(logger)

    def test_termination(self):
        """
        Returns true if the migration should abort
        :return:
        """
        if self.should_terminate:
            return self.should_terminate()
        return False

    def get_cur_version(self):
        """
        Current data version to get to
        :return:
        """
        return CUR_VERSION

    def get_db_version(self):
        """
        Returns Db version
        :return:
        """
        data = self.s.query(dbutil.AlembicDataMigration).first()
        if data is None:
            return 0

        return data.data_ver

    def _save_new_ver(self, ver):
        """
        Updates the data version
        :param ver:
        :return:
        """
        data = self.s.query(dbutil.AlembicDataMigration).first()
        if data is None:
            data = dbutil.AlembicDataMigration()
            data.schema_ver = 0
            data.data_ver = ver
            self.s.add(data)
            self.s.commit()
            return

        data.data_ver = ver
        self.s.commit()

    def migrate(self):
        """
        Main migration wrapper
        :return:
        """
        cur_ver = self.get_cur_version()
        db_ver = self.get_db_version()
        logger.info('Code version: %s, db version: %s' % (cur_ver, db_ver))
        if db_ver < 1:
            self._migrate_1()
        if db_ver < 2:
            self._migrate_2()

    #
    # Migration routines
    #

    def _migrate_1(self):
        """
        Add subj key info, authority key info to the certs
        Incremental migration process, chunk by chunk.
        :return:
        """
        logger.info('Migration 01: Computing subject key identifier for certificates')

        ignore_set = set()
        fatal_error = False
        migrate_continue = True
        dbcrt = dbutil.Certificate

        offset = 0
        page_size = 1000
        while not self.test_termination() and migrate_continue and not fatal_error:

            # per-chunk processing
            # finished with processing if there are no such certs without subj key info
            migrate_continue = True
            while migrate_continue and not fatal_error:
                res = self.s.query(dbcrt) \
                    .filter(dbcrt.subject_key_info == None) \
                    .filter(dbcrt.key_type != None)\
                    .filter(dbcrt.key_bit_size != None)\
                    .filter(dbcrt.pem != None) \
                    .order_by(dbcrt.id)\
                    .limit(page_size)\
                    .offset(offset)\
                    .all()

                if res is None or len(res) == 0:
                    migrate_continue = False
                    break

                all_ignored = sum([x.id in ignore_set for x in res]) == page_size
                if all_ignored:
                    offset += page_size
                    continue

                for cert_db in res:
                    if cert_db.id in ignore_set:
                        continue
                    try:
                        der = util.pem_to_der(cert_db.pem)
                        cert = util.load_x509_der(der)  # type: cryptography.x509.Certificate

                        cert_db.subject_key_info = util.take(util.lower(util.b16encode(
                            util.try_get_subject_key_identifier(cert))), 64)

                        cert_db.authority_key_info = util.take(util.lower(util.b16encode(
                            util.try_get_authority_key_identifier(cert))), 64)

                    except Exception as e:
                        logger.error('Error in migration certificate %s, exception: %s' % (cert_db.id, e))
                        self.trace_logger.log(e)
                        ignore_set.add(cert_db.id)

                self.s.flush()
                self.s.commit()
                self.s.expunge_all()

            if migrate_continue is False:
                logger.info('Migration 01: successfully migrated, skipped: %s' % len(ignore_set))
                self._save_new_ver(1)
                return

        if fatal_error:
            logger.info('Migration 01: please fix the error to continue with the migration')
        elif migrate_continue:
            logger.info('Migration 01: interrupted, will continue on next run')

    def _migrate_2(self):
        """
        PEM migrate
        :return:
        """
        logger.info('Migration 02: PEM migrate')

        ignore_set = set()
        fatal_error = False
        migrate_continue = True
        dbcrt = dbutil.Certificate

        offset = 0
        page_size = 1000
        while not self.test_termination() and migrate_continue and not fatal_error:

            # per-chunk processing
            migrate_continue = True
            while migrate_continue and not fatal_error:
                res = self.s.query(dbcrt)\
                    .filter(dbcrt.key_type != None)\
                    .filter(dbcrt.key_bit_size != None)\
                    .filter(dbcrt.pem != None)\
                    .order_by(dbcrt.id)\
                    .limit(page_size)\
                    .offset(offset)\
                    .all()

                if res is None or len(res) == 0:
                    migrate_continue = False
                    break

                for cert_db in res:
                    cert_db.pem = util.strip_pem(cert_db.pem)

                self.s.flush()
                self.s.commit()
                self.s.expunge_all()
                offset += page_size

            if migrate_continue is False:
                logger.info('Migration 02: successfully migrated')
                self._save_new_ver(2)
                return

        if fatal_error:
            logger.info('Migration 02: please fix the error to continue with the migration')
        elif migrate_continue:
            logger.info('Migration 02: interrupted, will continue on next run')

