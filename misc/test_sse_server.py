#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template
from flask_sse import sse
import argparse

app = Flask(__name__)
app.config['REDIS_URL'] = 'redis://localhost'
app.register_blueprint(sse, url_prefix='/stream')


def template():
    return '''
    <!DOCTYPE html>
<html>
<head>
  <title>Flask-SSE Quickstart</title>
</head>
<body>
  <h1>Flask-SSE Quickstart</h1>
  <script>
    var source = new EventSource("/stream");
    source.addEventListener('greeting', function(event) {
        var data = JSON.parse(event.data);
        alert("The server says " + data.message);
    }, false);
    source.addEventListener('error', function(event) {
        alert("Failed to connect to event stream. Is Redis running?");
    }, false);
  </script>
</body>
</html>
'''


@app.route('/')
def index():
    return template()


@app.route('/hello')
def publish_hello():
    sse.publish({"message": "Hello!"}, type='greeting')
    return "Message sent!"


def main():
    import eventlet
    from eventlet import wsgi

    parser = argparse.ArgumentParser(description='HTTP/2 ServerSentEvents server')
    parser.add_argument('-p', dest='port', default=5000, type=int, help='Port')
    args = parser.parse_args()

    listener = eventlet.listen(('0.0.0.0', args.port))
    wsgi.server(listener, app)


if __name__ == "__main__":
    main()


# or run with
# gunicorn test_sse_server:app --worker-class gevent --bind 127.0.0.1:5000

