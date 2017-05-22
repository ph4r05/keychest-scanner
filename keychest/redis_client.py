#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import redis
import lua_scripts
import logging

logger = logging.getLogger(__name__)


class RedisClient(object):
    def __init__(self):
        self.redis_pool = None
        self.redis = None

        self.lua_size = None
        self.lua_pop = None
        self.lua_release = None
        self.lua_migrate_expired_jobs = None

        self.pop_retry_after = 60
        self.default_queue = 'scanner'

    def init(self, config):
        """
        Configures new connection
        :param config: 
        :return: 
        """
        self.redis_pool = redis.ConnectionPool(host=config.redis_host, port=config.redis_port, db=0)
        self.redis = redis.Redis(connection_pool=self.redis_pool)

        # register scripts
        self.lua_size = self.redis.register_script(lua_scripts.lua_size())
        self.lua_pop = self.redis.register_script(lua_scripts.lua_pop())
        self.lua_release = self.redis.register_script(lua_scripts.lua_release())
        self.lua_migrate_expired_jobs = self.redis.register_script(lua_scripts.lua_migrate_expired_jobs())
        logger.debug('Redis client initialized')


