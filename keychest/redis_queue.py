#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import redis
import lua_scripts
from redis_client import RedisClient
from redis_job import RedisJob


class RedisQueue(object):
    def __init__(self, redis_client):
        self.redis = redis_client

        self.pop_retry_after = 60
        self.default_queue = 'scanner'

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

    def size(self, queue=None):
        """
        Length of the queue
        :param queue: 
        :return: 
        """
        q = self.get_queue(queue)
        return self.redis.lua_size(keys=[q, '%s:delayed' % q, '%s:reserved' % q])

    def push_raw(self, data, queue=None):
        """
        Pushes job to the queue
        :param data: 
        :param queue: 
        :return: 
        """
        return self.redis.redis.rpush(self.get_queue(queue), data)

    def later_raw(self, delay, data, queue=None):
        """
        Push a raw job onto the queue after a delay.
        :param delay: 
        :param data: 
        :param queue: 
        :return: 
        """
        return self.redis.redis.zadd('%s:delayed' % self.get_queue(queue), int((time.time() + delay)*1000), data)

    def pop(self, queue=None):
        """
        Pop the next job off of the queue.
        :param queue: 
        :return: 
        """
        q = self.get_queue(queue)

        job, reserved = self.retrieve_next_job(q)

        if reserved is not None:
            return RedisJob(None, self, job, reserved, None, q)

        return None

    def migrate_expired_jobs(self, qfrom, qto):
        """
        Migrate the delayed jobs that are ready to the regular queue.
        :param qfrom: 
        :param qto: 
        :return: 
        """
        return self.redis.lua_migrate_expired_jobs(keys=[qfrom, qto], args=[int(time.time()*1000)])

    def retrieve_next_job(self, queue):
        """
        Retrieves job from the redis queue - implemented as list
        :param queue: 
        :return: 
        """
        return self.redis.lua_pop(keys=[queue, '%s:reserved' % queue], args=[self.pop_retry_after])

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
        return self.redis.redis.zrem('%s:reserved' % self.get_queue(queue), job.get_reserved_job())

    def delete_and_release(self, queue, job, delay):
        """
        Delete a reserved job from the reserved queue and release it.
        :param queue: 
        :param job: 
        :param delay: 
        :return: 
        """
        q = self.get_queue(queue)
        return self.redis.lua_release(keys=['%s:delayed' % q, '%s:reserved' % q],
                                      args=[job.get_reserved_job(), int((time.time() + delay)*1000)])


