#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
REST API
"""

from trace_logger import Tracelogger
from dbutil import DbKeychestAgent, DbWatchTarget, DbLastScanCache, DbWatchService, DbBaseDomain, DbHelper
import util
import dbutil
from consts import DbLastScanCacheType, DbScanType

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
from datetime import datetime, timedelta
from functools import wraps

import sqlalchemy as salch

import eventlet
from eventlet import wsgi
eventlet.monkey_patch()

from flask import Flask, jsonify, request, abort
from flask_socketio import SocketIO, send as ws_send, emit as ws_emit
flask_sse = eventlet.import_patched('flask_sse')


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
        self.last_results = None


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

        self.use_websockets = True
        self.use_sse = True

        self.debug = False
        self.server = None
        self.config = None
        self.db = None

        self.flask = Flask(__name__)
        self.socket_io = None

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

    def wsgi_options(self):
        """
        Returns kwargs for wsgi server
        :return:
        """
        kwargs = dict()
        if self.use_sse:
            kwargs['minimum_chunk_size'] = 1
        return kwargs

    def init_server(self):
        """
        Initialize server
        :return:
        """
        self.flask.config['REDIS_URL'] = 'redis://localhost:6379'
        self.flask.config['SECRET_KEY'] = util.random_alphanum(16)

        if self.use_sse:
            self.flask.register_blueprint(flask_sse.sse, url_prefix='/stream')

        if self.use_websockets:
            self.socket_io = SocketIO(self.flask, async_mode='eventlet', policy_server=False,
                                      allow_upgrades=True, **self.wsgi_options())

            logger.info('SocketIO wrapper %s for Flask: %s' % (self.socket_io, self.flask))

    def work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('REST thread started %s %s %s dbg: %s'
                    % (os.getpid(), os.getppid(), threading.current_thread(), self.debug))
        try:
            self.init_server()
            self.init_rest()

            if self.use_websockets:
                self.serve_websockets()
            elif self.debug:
                self.serve_werkzeug()
            else:
                self.serve_eventlet()

            logger.info('Terminating flask: %s' % self.flask)

        except Exception as e:
            logger.error('Exception: %s' % e)
            logger.error(traceback.format_exc())

        self.terminating()
        logger.info('Work loop terminated')

    def serve_werkzeug(self):
        """
        Developer local server, not for production use
        :return:
        """
        r = self.flask.run(debug=self.debug, port=self.HTTP_PORT, threaded=True)
        logger.info('Started werkzeug server: %s' % r)

    def serve_eventlet(self):
        """
        Eventlet server, fast async, for production use
        :return:
        """
        listener = eventlet.listen(('0.0.0.0', self.HTTP_PORT))
        logger.info('Starting Eventlet listener %s for Flask %s' % (listener, self.flask))
        wsgi.server(listener, self.flask, **self.wsgi_options())

    def serve_websockets(self):
        """
        Classical Flask application + websocket support, using eventlet
        :return:
        """
        logger.info('Starting socket_io')
        self.socket_io.run(app=self.flask, host='0.0.0.0', port=self.HTTP_PORT, **self.wsgi_options())

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

        @self.flask.route('/api/v1.0/get_latest_results', methods=['GET'])
        def rest_get_latest_results():
            return self.on_get_latest_results(request=request)

        @self.flask.route('/api/v1.0/new_results', methods=['GET', 'POST'])
        def rest_new_result():
            return self.on_new_results(request=request)

        @self.flask.route('/api/v1.0/test_sse')
        def send_message():
            flask_sse.sse.publish({'message': 'Hello!'}, type='greeting')
            return 'Message sent!'

        @self.socket_io.on('message', namespace='/ws')
        def handle_message(message):
            print('received message: ' + message)
            ws_send(reversed(str(message)))
            ws_emit('my response', {'data': 'got it!'})

        @self.socket_io.on('connect', namespace='/ws')
        def test_connect():
            logger.info('WS connected')

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

    #
    # Data methods
    #

    def _get_last_scans(self, s, r):
        """
        Returns last cached scans IDs.
        :param r:
        :return:
        """
        lasts = s.query(DbLastScanCache) \
            .join(DbWatchTarget, salch.and_(
                DbLastScanCache.cache_type == DbLastScanCacheType.AGENT_SCAN,
                DbLastScanCache.scan_type.in_([DbScanType.DNS, DbScanType.TLS]),
                DbLastScanCache.obj_id == DbWatchTarget.id)) \
            .filter(DbWatchTarget.agent_id == r.agent.id) \
            .all()
        return lasts

    #
    # Handlers
    #

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
        recs = s.query(DbWatchTarget, DbWatchService, DbBaseDomain)\
            .outerjoin(DbWatchService, DbWatchService.id == DbWatchTarget.service_id)\
            .outerjoin(DbBaseDomain, DbBaseDomain.id == DbWatchTarget.top_domain_id)\
            .filter(DbWatchTarget.agent_id == r.agent.id).all()

        def sub_proc(rec):
            rec[0].trans_service = rec[1]
            rec[0].trans_top_domain = rec[2]
            return rec[0]

        recs_proc = [sub_proc(rec) for rec in recs]
        cols = DbWatchTarget.__table__.columns + [
            dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_service'), DbHelper.to_dict),
            dbutil.ColTransformWrapper(dbutil.TransientCol(name='trans_top_domain'), DbHelper.to_dict)
        ]
        dicts = [DbHelper.to_dict(x, cols=cols) for x in recs_proc]
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

    @wrap_requests()
    def on_get_latest_results(self, r=None, request=None):
        """
        Used to get our latest results about the watch id.
        Agent will then feed us all the previous results up to the latest one via `new_results`.
        Request format:
            [{watch_id: 1, scan_type:0 optional}, ...]
        If empty returns all last results received from the remote site.

        Helps with implementing reliable scrolling/streaming interface.
        We cache the last results seen by the agent so we are sure we get all collected results.

        :param r:
        :rtype r: AugmentedRequest
        :param request:
        :return:
        """
        s = r.s
        lasts = self._get_last_scans(s, r)
        lasts = [DbHelper.to_dict(x) for x in lasts]
        lasts = [util.jsonify(x) for x in lasts]
        return jsonify({'result': True, 'last_results': lasts})

    @wrap_requests()
    def on_new_results(self, r=None, request=None):
        """
        Called on scan returned a new result.
        Heavy lifting method for processing results data sent from the agent.

        data.json = {scans:[ res ]}
        res = {new_scan: nr, prev_scan_id: lr}

        We might check for last results and if prev result does not match our result just reject this update.
        Client then should ask for last scan IDs and push all missing ones.

        To make it simple for now we skip this check by client passing data.json['sorry'] = 1.
        This also has a legitimate use when agent just does not have last scan as master desires.

        One request should contain scans only for one hosts so rejection affects only the single host.

        Simple agent implementation could do scanning independently (no result push) and then triggering an update
        mechanism / having another publishing thread that asks for latest scans IDs and publishing new ones.
        This enables

        :param r:
        :param request:
        :return:
        """
        # logger.debug(request)
        # logger.debug(json.dumps(request.json, indent=2))

        # r.last_results = self._get_last_scans(r.s, r)
        self.server.agent_on_new_results(r.s, r, request.json)
        return jsonify({'result': True})


