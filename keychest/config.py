#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import collections
import logging


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class Config(object):
    """Configuration object, handles file read/write"""

    # noinspection PyUnusedLocal
    def __init__(self, json_db=None, *args, **kwargs):
        self.json = json_db

    @classmethod
    def from_json(cls, json_string):
        return cls(json_db=json.loads(json_string, object_pairs_hook=collections.OrderedDict))

    @classmethod
    def from_file(cls, file_name):
        with open(file_name, 'r') as f:
            read_lines = [x.strip() for x in f.read().split('\n')]
            lines = []
            for line in read_lines:
                if line.startswith('//'):
                    continue
                lines.append(line)

            return Config.from_json('\n'.join(lines))

    @classmethod
    def default_config(cls):
        def_cfg = collections.OrderedDict()
        def_cfg['mysql_db'] = 'keychest'
        def_cfg['mysql_user'] = 'keychest'
        def_cfg['mysql_password'] = 'keychest'
        def_cfg['redis_host'] = '127.0.0.1'
        def_cfg['redis_port'] = 6379
        def_cfg['workers'] = 10

        root = collections.OrderedDict()
        root['config'] = def_cfg
        return cls(json_db=root)

    def ensure_config(self):
        if self.json is None:
            self.json = collections.OrderedDict()
        if 'config' not in self.json:
            self.json['config'] = collections.OrderedDict()

    def has_nonempty_config(self):
        return self.json is not None and 'config' in self.json and len(self.json['config']) > 0

    def get_config(self, key, default=None):
        if not self.has_nonempty_config():
            return default
        return self.json['config'][key] if key in self.json['config'] else default

    def set_config(self, key, val):
        self.ensure_config()
        self.json['config'][key] = val

    def to_string(self):
        return json.dumps(self.json, indent=2) if self.has_nonempty_config() else ""

    # MySQL user
    @property
    def mysql_db(self):
        return self.get_config('mysql_db')

    @mysql_db.setter
    def mysql_db(self, val):
        self.set_config('mysql_db', val)

    # MySQL user
    @property
    def mysql_user(self):
        return self.get_config('mysql_user')

    @mysql_user.setter
    def mysql_user(self, val):
        self.set_config('mysql_user', val)

    # MySQL password for the state table store
    @property
    def mysql_password(self):
        return self.get_config('mysql_password')

    @mysql_password.setter
    def mysql_password(self, val):
        self.set_config('mysql_password', val)

    # Redis host name
    @property
    def redis_host(self):
        return self.get_config('redis_host', '127.0.0.1')

    @redis_host.setter
    def redis_host(self, val):
        self.set_config('redis_host', val)

    # Redis port number
    @property
    def redis_port(self):
        return self.get_config('redis_port', 6379)

    @redis_port.setter
    def redis_port(self, val):
        self.set_config('redis_port', val)

    # Redis port number
    @property
    def workers(self):
        return self.get_config('workers', 10)

    @workers.setter
    def workers(self, val):
        self.set_config('workers', val)




