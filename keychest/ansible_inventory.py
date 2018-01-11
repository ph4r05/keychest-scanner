#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import os
import sys
from datetime import datetime, date
import re
import time
import shutil
import argparse
import coloredlogs
import base64
import collections

from .dbutil import MySQL, DbManagedHost, DbHostGroup, DbHostToGroupAssoc, DbSshKey
from .config import Config
from .core import Core
from . import util
from . import util_keychest

import sqlalchemy as salch

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class AnsibleInventory(object):
    """
    Loading the Ansible inventory
    """

    def __init__(self, **kwargs):
        self.config = None
        self.db = None
        self.decryptor = None  # type: util_keychest.Encryptor

        self.cache_path_cache = None
        self.cache_max_age = 60*60
        self.cache_path_cache = None
        self.cache_path_inventory = None
        self.latest_change = None

        self.conn = None
        self.inventory = dict()  # A list of groups and the hosts in that group
        self.cache = dict()  # Details about hosts in the inventory

    def init_config(self):
        """
        Config init
        :return:
        """
        self.config = Core.read_configuration()  # type: Config
        if self.config is None or not self.config.has_nonempty_config():
            sys.stderr.write('Configuration is empty: %s\nCreating default one... (fill in access credentials)\n'
                             % Core.get_config_file_path())

            Core.write_configuration(Config.default_config())
            return 1

        if util.is_empty(self.config.keychest_key):
            raise ValueError('KeyChest app key is empty')

        self.decryptor = util_keychest.Encryptor(app_key=base64.b64decode(self.config.keychest_key))

    def init_db(self):
        """
        DB initialization
        :return:
        """
        self.db = MySQL(config=self.config)
        self.db.init_db()

    def clean_caches(self):
        """
        Cleans all cached info
        :return:
        """
        cdir = self.config.ansible_cache
        if cdir is None:
            return
        shutil.rmtree(cdir, True)

    def get_latest_time_modif(self):
        """
        Loads latest DB modification time - rebuild the caches?
        :return:
        """
        s = self.db.get_session()
        try:
            host_data = s.query(
                salch.func.max(DbManagedHost.created_at),
                salch.func.max(DbManagedHost.updated_at),
                salch.func.max(DbManagedHost.deleted_at)).first()

            grp_data = s.query(
                salch.func.max(DbHostGroup.created_at),
                salch.func.max(DbHostGroup.updated_at),
                salch.func.max(DbHostGroup.deleted_at)).first()

            host2grp = s.query(
                salch.func.max(DbHostToGroupAssoc.created_at),
                salch.func.max(DbHostToGroupAssoc.updated_at),
                salch.func.max(DbHostToGroupAssoc.deleted_at)).first()

            latest = max(util.compact(host_data + grp_data + host2grp))
            return latest

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

    def process(self):
        """
        Main entry point
        :return:
        """
        self.init_config()
        self.init_db()

        if util.is_empty(self.config.ansible_cache):
            raise ValueError('ansible_cache config is empty')
        if util.is_empty(self.config.ansible_sshkeys):
            raise ValueError('ansible_sshkeys config is empty')

        self.cache_path_cache = self.config.ansible_cache
        self.cache_path_cache = os.path.join(self.config.ansible_cache, 'ansible.cache')
        self.cache_path_inventory = os.path.join(self.config.ansible_cache, 'ansible.index')
        self.latest_change = self.get_latest_time_modif()

        util.makedirs(self.config.ansible_sshkeys)
        util.makedirs(self.config.ansible_cache)

        # Cache
        if self.args.refresh_cache:
            self.update_cache()
        elif not self.is_cache_valid():
            self.update_cache()
        else:
            self.load_inventory_from_cache()
            self.load_cache_from_cache()

        data_to_print = ''

        # Data to print
        if self.args.host:
            data_to_print += self.get_host_info()
        else:
            self.inventory['_meta'] = {'hostvars': collections.OrderedDict()}
            for hostname in self.cache:
                self.inventory['_meta']['hostvars'][hostname] = self.cache[hostname]
            data_to_print += self.json_format_dict(self.inventory, True)

        print(data_to_print)

    def is_cache_valid(self):
        """
        Determines if the cache files have expired, or if it is still valid
        :return:
        """
        if os.path.isfile(self.cache_path_cache):
            mod_time = os.path.getmtime(self.cache_path_cache)
            current_time = time.time()

            if (mod_time + self.cache_max_age) > current_time \
                    and (self.latest_change is None or self.latest_change < datetime.fromtimestamp(mod_time)):

                if os.path.isfile(self.cache_path_inventory):
                    return True

        return False

    def get_sshkey_fname(self, sshkey):
        """
        SSH key file name
        :param sshkey:
        :return:
        """
        return os.path.join(self.config.ansible_sshkeys, 'sshkey-%04d.pem' % sshkey.id)

    def update_cache(self):
        """
        Make calls to cobbler and save the output in a cache
        :return:
        """
        self.groups = dict()
        self.hosts = dict()

        s = self.db.get_session()
        try:
            hosts = s.query(DbManagedHost)\
                .filter(DbManagedHost.deleted_at==None)\
                .filter(DbManagedHost.has_ansible==1)\
                .all()

            all_hostnames = []
            for host in hosts:  # type: DbManagedHost
                sshkey_path = None
                all_hostnames.append(host.host_addr)

                # SSH key sync, extract to a file
                if host.ssh_key is not None:
                    sshkey_path = self.get_sshkey_fname(host.ssh_key)

                    # Dump SSH key if does not exist.
                    if not os.path.exists(sshkey_path):
                        with util.safe_open(sshkey_path, 'w', chmod=0o600) as fh:
                            fh.write(self.decryptor.decrypt(host.ssh_key.priv_key))

                # Host data
                host_obj = collections.OrderedDict()
                host_obj['hostname'] = host.host_name
                host_obj['owner'] = host.owner_id
                host_obj['host_os'] = host.host_os
                host_obj['host_os_ver'] = host.host_os_ver

                host_obj['ansible_connection'] = 'ssh'
                if host.ssh_user:
                    host_obj['ansible_user'] = host.ssh_user
                if sshkey_path:
                    host_obj['ansible_ssh_private_key_file'] = sshkey_path

                self.cache[host.host_addr] = host_obj

            self.inventory['all'] = all_hostnames
            groups = s.query(DbHostGroup)\
                .filter(DbHostGroup.deleted_at==None)\
                .all()

            for group in groups:  # type: DbHostGroup
                host_names = []
                for host_assoc in group.hosts:  # type: DbHostToGroupAssoc
                    host = host_assoc.host
                    if host.has_ansible:
                        host_names.append(host.host_addr)

                if len(host_names) > 0:
                    self.inventory[group.group_name] = host_names

        finally:
            util.silent_expunge_all(s)
            util.silent_close(s)

        self.write_to_cache(self.cache, self.cache_path_cache)
        self.write_to_cache(self.inventory, self.cache_path_inventory)

    def get_host_info(self):
        """
        Get variables about a specific host
        :return:
        """
        if not self.cache or len(self.cache) == 0:
            # Need to load index from cache
            self.load_cache_from_cache()

        if self.args.host not in self.cache:
            # try updating the cache
            self.update_cache()

            if self.args.host not in self.cache:
                # host might not exist anymore
                return self.json_format_dict({}, True)

        return self.json_format_dict(self.cache[self.args.host], True)

    def push(self, my_dict, key, element):
        """
        Pushed an element onto an array that may not have been defined in the dict
        :param my_dict:
        :param key:
        :param element:
        :return:
        """
        if key in my_dict:
            my_dict[key].append(element)
        else:
            my_dict[key] = [element]

    def load_inventory_from_cache(self):
        """
        Reads the index from the cache file sets self.index
        :return:
        """
        cache = open(self.cache_path_inventory, 'r')
        json_inventory = cache.read()
        self.inventory = json.loads(json_inventory)

    def load_cache_from_cache(self):
        """
        Reads the cache from the cache file sets self.cache
        :return:
        """
        cache = open(self.cache_path_cache, 'r')
        json_cache = cache.read()
        self.cache = json.loads(json_cache)

    def write_to_cache(self, data, filename):
        """
        Writes data in JSON format to a file
        :param data:
        :param filename:
        :return:
        """
        json_data = self.json_format_dict(data, True)
        cache = open(filename, 'w')
        cache.write(json_data)
        cache.close()

    def to_safe(self, word):
        """
        Converts 'bad' characters in a string to underscores so they can be used as Ansible groups
        :param word:
        :return:
        """
        return re.sub(r'[^A-Za-z0-9\-]', '_', word)

    def json_format_dict(self, data, pretty=False):
        """
        Converts a dict to a JSON object and dumps it as a formatted string
        :param data:
        :param pretty:
        :return:
        """
        if pretty:
            return json.dumps(data, sort_keys=True, indent=2)
        else:
            return json.dumps(data)

    def app_main(self):
        """
        Argument parsing & startup
        :return:
        """
        # Parse our argument list
        parser = argparse.ArgumentParser(description='KeyChest Ansible inventory')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='enables debug mode')

        parser.add_argument('--refresh_cache', action='store_true', default=False,
                            help='Forcefully refresh caches')

        parser.add_argument('--list', action='store_true', default=True,
                            help='List instances (default: True)')

        parser.add_argument('--host', action='store',
                            help='Get all the variables about a specific instance')

        self.args = parser.parse_args()
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        util.install_sarge_filter()
        self.process()


def main():
    """
    Main server starter
    :return:
    """
    app = AnsibleInventory()
    app.app_main()


if __name__ == '__main__':
    main()

