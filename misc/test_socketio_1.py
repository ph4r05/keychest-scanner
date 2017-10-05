#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from flask import Flask
from flask_socketio import SocketIO, send as ws_send, emit as ws_emit

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


flask = Flask(__name__)
flask.config['REDIS_URL'] = 'redis://localhost:6379'
flask.config['SECRET_KEY'] = 'secret!'
# flask.config['DEBUG'] = True
# flask.register_blueprint(sse, url_prefix='/stream')
socket_io = SocketIO(flask, async_mode='eventlet', policy_server=False, allow_upgrades=True)

@flask.route('/api/v1.0/keepalive', methods=['GET'])
def keep_alive():
    return 'ok'

@flask.route('/stream')
def send_messagex():
    logger.info('streeeeeam')
    # sse.publish({'message': 'Hello!'}, type='greeting')
    return 'Message sent!'

@socket_io.on('message', namespace='/ws')
def handle_message(message):
    print('received message: ' + message)
    ws_send(reversed(str(message)))
    ws_emit('my response', {'data': 'got it!'})

@socket_io.on('connect', namespace='/ws')
def test_connect():
    logger.info('WS connected')

socket_io.run(flask, port=33080, host='0.0.0.0')

