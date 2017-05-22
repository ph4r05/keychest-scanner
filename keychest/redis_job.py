#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import util


class RedisJob(object):
    def __init__(self, container, redis, job, reserved, connection_name, queue):
        self.job = job
        self.redis = redis
        self.queue = queue
        self.reserved = reserved
        self.container = container
        self.connection_name = connection_name

        self.deleted = False
        self.released = False
        self.failed = False

        self.decoded = self.payload()

    def get_raw_body(self):
        """
        Get the raw body string for the job.
        :return: 
        """
        return self.job

    def delete(self):
        """
        Delete the job from the queue.
        :return: 
        """
        self.deleted = True
        self.redis.delete_reserved(self.queue, self)

    def release(self, delay=0):
        """
        Release the job
        :return: 
        """
        self.released = True
        self.redis.delete_and_release(self.queue, self, delay)

    def attempts(self):
        """
        Get the number of times the job has been attempted.
        :return: 
        """
        return util.defvalkey(self.decoded, 'attempts', 0) + 1

    def get_job_id(self):
        """
        Get the job identifier.
        :return: 
        """
        return util.defvalkey(self.decoded, 'id')

    def get_redis_queue(self):
        """
        Get the underlying Redis factory implementation.
        :return: 
        """
        return self.redis

    def get_reserved_job(self):
        """
        Get the underlying reserved Redis job.
        :return: 
        """
        return self.reserved

    def payload(self):
        """
        Get the decoded body of the job.
        :return: 
        """
        return json.loads(self.get_raw_body())

    def max_tries(self):
        """
        The number of times to attempt a job.
        :return: 
        """
        return util.defvalkey(self.payload(), 'maxTries')

    def timeout(self):
        """
        The number of seconds the job can run.
        :return: 
        """
        return util.defvalkey(self.payload(), 'timeout')

    def get_name(self):
        """
        Get the name of the queued job class.
        :return: 
        """
        return self.payload()['job']


