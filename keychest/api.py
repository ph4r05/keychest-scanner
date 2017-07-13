#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
REST API
"""

from dbutil import DbKeychestAgent
import util

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
        self.api_key = None
        self.agent = None


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
            r = self.flask.run(debug=self.debug, port=self.HTTP_PORT)
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
            return self.on_keep_alive(request)

        @self.flask.route('/api/v1.0/get_targets', methods=['GET'])
        def rest_stats():
            return self.on_get_targets(request)

    def auth_request(self, request):
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
        s = self.db.get_session()
        try:
            r.agent = s.query(DbKeychestAgent).filter(DbKeychestAgent.api_key == r.api_key).first()
        finally:
            util.silent_close(s)

        if r.agent is None:
            logger.warning('Agent API key not found: %s' % util.take(r.api_key, 64))
            abort(403)

        self.local_data.r = r
        return r

    def process_payload(self, request):
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

    def on_keep_alive(self, request=None):
        """
        Simple keepalive
        :param request:
        :return:
        """
        return jsonify({'result': True})

    def on_get_targets(self, request=None):
        """
        Loads watch targets for sync.
        :param request:
        :return:
        """
        self.auth_request(request)

        return jsonify({'result': True})

