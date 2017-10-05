#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import coloredlogs
import logging
import argparse
import random
import string
from flask import Flask

import eventlet
from eventlet import wsgi

# Uncomment for eventlet
# eventlet.monkey_patch()
# flask_sse = eventlet.import_patched('flask_sse')

# Uncomment for gunicorn
import flask_sse

app = Flask(__name__)
app.config['REDIS_URL'] = 'redis://127.0.0.1:6379'
app.register_blueprint(flask_sse.sse, url_prefix='/stream')


def template():
    return '''
    <!DOCTYPE html>
<html>
<head>
  <title>Flask-SSE Quickstart</title>
</head>
<body>
  <h1>Flask-SSE Quickstart</h1>
  <p>
    Now open <a href="/hello" target="_blank">/hello</a> in a new tab to send the message
  </p>
  
  <pre id="pre">
  </pre>
  
  <script>
    var source = new EventSource("/stream");
    source.addEventListener('greeting', function(event) {
        var data = JSON.parse(event.data);
        console.log("The server says " + data.message);
        
        var br = document.createElement("span");
        br.appendChild(document.createTextNode(data.message + "\\n"));
        document.getElementById('pre').appendChild(br);
        
    }, false);
    source.addEventListener('error', function(event) {
        console.warn("Failed to connect to event stream. Is Redis running?");
    }, false);
  </script>
</body>
</html>
'''


def rand():
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(8))


@app.route('/')
def index():
    return template()


@app.route('/hello')
def publish_hello():
    flask_sse.sse.publish({"message": "Hello! " + rand()}, type='greeting')
    return "Message sent!"


def main():
    parser = argparse.ArgumentParser(description='HTTP/2 ServerSentEvents server')
    parser.add_argument('-p', dest='port', default=5000, type=int, help='Port')
    args = parser.parse_args()

    listener = eventlet.listen(('0.0.0.0', args.port))
    wsgi.server(listener, app)


if __name__ == "__main__":
    main()


# or run with
# gunicorn test_sse_server:app --worker-class gevent --bind 127.0.0.1:5000

