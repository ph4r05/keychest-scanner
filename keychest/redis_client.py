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

    #
    # Queue
    #

    def get_queue(self, queue=None):
        """
        Queue getter / default
        :param queue: 
        :return: 
        """
        if queue is None:
            return self.default_queue
        return queue

    def queue_size(self, queue=None):
        """
        Length of the queue
        :param queue: 
        :return: 
        """
        q = self.get_queue(queue)
        return self.lua_size(keys=[q, '%s:delayed' % q, '%s:reserved' % q])

    def queue_push_raw(self, data, queue=None):
        """
        Pushes job to the queue
        :param data: 
        :param queue: 
        :return: 
        """
        return self.redis.rpush(self.get_queue(queue), data)

    def queue_later_raw(self, delay, data, queue=None):
        """
        Push a raw job onto the queue after a delay.
        :param delay: 
        :param data: 
        :param queue: 
        :return: 
        """
        return self.redis.zadd('%s:delayed' % self.get_queue(queue), int((time.time() + delay)*1000), data)

    def queue_pop(self, queue=None):
        """
        Pop the next job off of the queue.
        :param queue: 
        :return: 
        """
        q = self.get_queue(queue)

        job, reserved = self.retrieve_next_job(q)

        if reserved is not None:
            return job, reserved

        return None, None

    def migrate_expired_jobs(self, qfrom, qto):
        """
        Migrate the delayed jobs that are ready to the regular queue.
        :param qfrom: 
        :param qto: 
        :return: 
        """
        return self.lua_migrate_expired_jobs(keys=[qfrom, qto], args=[int(time.time()*1000)])

    def retrieve_next_job(self, queue):
        """
        Retrieves job from the redis queue - implemented as list
        :param queue: 
        :return: 
        """
        return self.lua_pop(keys=[queue, '%s:reserved' % queue], args=[self.pop_retry_after])

    def migrate(self, queue):
        """
        Migrate any delayed or expired jobs onto the primary queue.
        :param queue: 
        :return: 
        """
        self.migrate_expired_jobs('%s:delayed' % queue, queue)

        if self.pop_retry_after is not None:
            self.migrate_expired_jobs('%s:reserved' % queue, queue)

    def delete_reserved(self, queue, job):
        """
        Delete a reserved job from the queue.
        :param queue: 
        :param job: 
        :return: 
        """
        return self.redis.zrem('%s:reserved' % self.get_queue(queue), job)  # TODO: reservedJob

    def delete_and_release(self, queue, job, delay):
        """
        Delete a reserved job from the reserved queue and release it.
        :param queue: 
        :param job: 
        :param delay: 
        :return: 
        """
        q = self.get_queue(queue)
        return self.lua_release(keys=['%s:delayed' % q, '%s:reserved' % q], args=[job, int((time.time() + delay)*1000)])


