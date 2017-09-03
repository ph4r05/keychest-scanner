#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import coloredlogs
import os
import re

import util
import dbutil
from core import Core
from config import Config

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


DB_BACKUPS = '/tmp'
DB_NAME = 'keychest'
KC_USER = 'keychest'


class CmdSetup(object):
    """
    Simple KeyChest setup utility
    """

    def __init__(self):
        self.args = None
        self.db = None
        self.config = None
        self.user_passwd = None

    def init_root_db(self):
        """
        Init root db connection
        :return:
        """
        conn_string = 'mysql://%s:%s@%s%s' % ('root', self._root_passwd(), '127.0.0.1', ':3306')
        self.db = dbutil.MySQL()
        self.db.build_engine(connstring=conn_string)
        self.db.session = dbutil.scoped_session(dbutil.sessionmaker(bind=self.db.engine))

    def drop_db(self):
        """
        Drops database
        :return:
        """
        self.init_root_db()

        self.db.backup_database(database_name=DB_NAME, backup_dir=DB_BACKUPS, root_passwd=self._root_passwd())
        self.db.drop_database(database_name=DB_NAME)

    def init_db(self):
        """
        Initialize DB scheme
        :return:
        """
        self.init_root_db()

        self.db.backup_database(database_name=DB_NAME, backup_dir=DB_BACKUPS, root_passwd=self._root_passwd())
        self.db.drop_database(database_name=DB_NAME)
        self.db.create_database(DB_NAME)
        self.db.create_user(KC_USER, self._user_passwd(), DB_NAME)
        logger.info('Database re-created, password: %s' % self._user_passwd())

        # Init config file
        self.sync_config()

    def sync_config(self):
        """
        Config file sync
        :return:
        """
        self.config = Core.read_configuration()
        if self.config is None or not self.config.has_nonempty_config():
            logger.info('Configuration is empty: %s\nCreating default one...' % Core.get_config_file_path())

            Core.write_configuration(Config.default_config())
            self.config = Core.read_configuration()
            self.config.mysql_db = DB_NAME
            self.config.mysql_user = KC_USER

        if not util.is_empty(self.user_passwd):
            self.config.mysql_password = self.user_passwd
        else:
            self.user_passwd = self.config.mysql_password

        Core.write_configuration(self.config)
        logger.info('Config file updated')

    def read_config(self):
        """
        Reads config
        :return:
        """
        self.config = Core.read_configuration()
        if self.config is None or not self.config.has_nonempty_config():
            raise Exception('Config is not initialized')

    def init_alembic(self):
        """
        Alembic config file init
        :return:
        """
        if util.is_empty(self.user_passwd):
            self.read_config()
            self.user_passwd = self.config.mysql_password

        with open('alembic.ini.example', 'rb') as fh:
            data = fh.read()

        conn_string = 'mysql://%s:%s@%s%s/%s' % (KC_USER, self._user_passwd(), '127.0.0.1', ':3306', DB_NAME)
        data = re.sub(r'^\s*sqlalchemy\.url\s*=.+?$', 'sqlalchemy.url = %s' % conn_string, data, flags=re.MULTILINE)
        with open('alembic.ini', 'wb') as fh:
            fh.write(data)

    def process(self):
        """
        Main entry
        :return:
        """
        if self.args.drop_db:
            self.drop_db()

        if self.args.init_db:
            self.init_db()

        if self.args.init_alembic:
            self.init_alembic()

    def _root_passwd(self):
        """
        mysql root pass
        :return:
        """
        return '' if self.args.root_passwd is None else self.args.root_passwd

    def _user_passwd(self):
        """
        User password
        :return:
        """
        if self.user_passwd:
            return self.user_passwd

        if util.is_empty(self.user_passwd) and self.args.kc_passwd:
            self.user_passwd = self.args.kc_passwd

        if util.is_empty(self.user_passwd):
            self.user_passwd = util.random_alphanum(16)

        return self.user_passwd

    def app_main(self):
        """
        Argument parsing & startup
        :return:
        """
        # Parse our argument list
        parser = argparse.ArgumentParser(description='KeyChest setup utility')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='enables debug mode')

        parser.add_argument('--root-pass', dest='root_passwd', default=None,
                            help='MySQL root password for DB init')

        parser.add_argument('--kc-pass', dest='kc_passwd', default=None,
                            help='MySQL KeyChest password for DB init. '
                                 'If None is given a new random password is generated')

        parser.add_argument('--drop-db', dest='drop_db', default=False, action='store_const', const=True,
                            help='Drops previous KeyChest database')

        parser.add_argument('--init-db', dest='init_db', default=False, action='store_const', const=True,
                            help='Drops previous KeyChest database & creates a new one')

        parser.add_argument('--init-alembic', dest='init_alembic', default=False, action='store_const', const=True,
                            help='Initializes alembic config file in the current directory')

        self.args = parser.parse_args()
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.process()


def main():
    """
    Main server starter
    :return:
    """
    app = CmdSetup()
    app.app_main()


if __name__ == '__main__':
    main()

