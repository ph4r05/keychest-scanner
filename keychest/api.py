#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
REST API
"""

from trace_logger import Tracelogger
from dbutil import DbKeychestAgent, DbWatchTarget, DbHelper
import util
import dbutil

import threading
import pid
import time
import os
import sys
import util
import json
import itertools
import argparse
import calendar
from threading import RLock as RLock
import logging
import coloredlogs
import traceback
import collections
from functools import wraps
from flask import Flask, jsonify, request, abort
from datetime import datetime, timedelta
import sqlalchemy as salch

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class AugmentedRequest(object):
    """
    Augmented request object with metadata
    """
    def __init__(self, req=None):
        self.req = req
        self.s = None  # session
        self.api_key = None
        self.ip = None
        self.agent = None  # type: DbKeychestAgent


class RestAPI(object):
    """
    Main server object
    """
    HTTP_PORT = 33080
    HTTPS_PORT = 33443
    API_HEADER = 'X-Auth-API'

    def __init__(self):
        self.running = True
        self.run_thread = None
        self.stop_event = threading.Event()
        self.local_data = threading.local()
        self.trace_logger = Tracelogger(logger)

        self.debug = False
        self.server = None
        self.config = None
        self.db = None

        self.flask = Flask(__name__)

    #
    # Management
    #

    def shutdown_server(self):
        """
        Shutdown flask server
        :return:
        """
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()

    def terminating(self):
        """
        Set state to terminating
        :return:
        """
        self.running = False
        self.stop_event.set()

    def work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('REST thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            self.init_rest()
            r = self.flask.run(debug=self.debug, port=self.HTTP_PORT, threaded=True)
            logger.info('Terminating flask: %s' % r)

        except Exception as e:
            logger.error('Exception: %s' % e)
            logger.error(traceback.format_exc())

        self.terminating()
        logger.info('Work loop terminated')

    def start(self):
        """
        Starts serving thread
        :return:
        """
        self.run_thread = threading.Thread(target=self.work, args=())
        self.run_thread.setDaemon(True)
        self.run_thread.start()

    #
    # REST interface
    #

    def init_rest(self):
        """
        Initializes rest server
        TODO: auth for dump, up, down - encrypt time token.
        :return:
        """

        @self.flask.route('/api/v1.0/keepalive', methods=['GET'])
        def keep_alive():
            return self.on_keep_alive(request=request)

        @self.flask.route('/api/v1.0/get_targets', methods=['GET'])
        def rest_get_targets():
            return self.on_get_targets(request=request)

        @self.flask.route('/api/v1.0/wait_command', methods=['GET'])
        def rest_wait_command():
            return self.on_wait_command(request=request)

    def wrap_requests(*args0, **kwargs0):
        """
        Function decorator for requests call, wrapping in try-catch, catching exceptions
        :return:
        """
        def wrap_requests_decorator(*args):
            f = args[0]

            @wraps(f)
            def wrapper(*args, **kwds):
                # noinspection PyBroadException
                self = args[0]
                r = None
                try:
                    r = self._auth_request(kwds.get('request', None))
                    args = list(args)[1:]
                    res = f(self, r, *args, **kwds)
                    return res

                except Exception as e:
                    logger.error('Uncaught exception: %s' % e)
                    self.trace_logger.log(e)

                finally:
                    if r is not None:
                        util.silent_close(r.s)

                # fail
                abort(500)

            return wrapper
        return wrap_requests_decorator

    def _auth_request(self, request):
        """
        Request authentization.
        API key has to be in the headers X-Auth-API: key
        If auth fails abort(403) is issued.
        :param request:
        :return:
        :rtype: AugmentedRequest
        """
        r = AugmentedRequest(request)
        if not request:
            logger.warning('Invalid request')
            abort(400)

        if self.API_HEADER not in request.headers:
            logger.warning('Invalid request - no auth header')
            abort(400)

        r.api_key = request.headers[self.API_HEADER]
        r.s = s = self.db.get_session()

        r.agent = s.query(DbKeychestAgent).filter(DbKeychestAgent.api_key == r.api_key).first()
        if r.agent is None:
            logger.warning('Agent API key not found: %s' % util.take(r.api_key, 64))
            abort(403)

        r.ip = request.remote_addr
        self._update_last_seen(s, r)
        s.commit()

        self.local_data.r = r
        return r

    def _process_payload(self, request):
        """
        Decrypts payload, fails request in case of a problem
        :param request:
        :return:
        """
        if not request.json or 'data' not in request.json:
            logger.warning('Invalid request')
            abort(400)

        data = request.json['data']
        js = util.unprotect_payload(data, self.config)

        if time.time() - js['time'] > 60:
            logger.warning('Client change update too old')
            abort(403)
        return js

    def _update_last_seen(self, s, r):
        """
        Updates last seen indicator for agent record
        :param s:
        :param r:
        :type r: AugmentedRequest
        :return:
        """
        # update cached last dns scan id
        stmt = salch.update(DbKeychestAgent) \
            .where(DbKeychestAgent.api_key == r.api_key) \
            .values(last_seen_active_at=salch.func.now(), last_seen_ip=r.ip)
        s.execute(stmt)

    def on_keep_alive(self, request=None):
        """
        Simple keepalive
        :param request:
        :return:
        """
        return jsonify({'result': True})

    @wrap_requests()
    def on_get_targets(self, r=None, request=None):
        """
        Loads watch targets for sync.
        :param r:
        :param request:
        :return:
        """
        s = r.s
        recs = s.query(DbWatchTarget).filter(DbWatchTarget.agent_id == r.agent.id).all()
        dicts = [DbHelper.to_dict(x) for x in recs]
        dicts = [util.jsonify(x) for x in dicts]
        return jsonify({'result': True, 'targets': dicts})

    @wrap_requests()
    def on_wait_command(self, r=None, request=None):
        """
        Commet like command push
        :param r:
        :param request:
        :return:
        """
        cmds = []

        # TODO: pull commands from the queue somehow
        start_time = time.time()
        thresh = start_time + 10.0
        while True:
            ctime = time.time()
            if ctime >= thresh:
                break

        return jsonify({'result': True, 'commands': []})

