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
redis = eventlet.import_patched('redis')


# Uncomment for gunicorn
# import flask_sse


from collections import OrderedDict
from flask import Blueprint, request, current_app, json, stream_with_context
import six

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


# import redis
# import redis.connection
pool = redis.BlockingConnectionPool(connection_class=redis.connection.Connection,
                                    max_connections=250, timeout=5, queue_class=eventlet.queue.LifoQueue, db=1)



@six.python_2_unicode_compatible
class Message(object):
    """
    Data that is published as a server-sent event.
    """
    def __init__(self, data, type=None, id=None, retry=None):
        """
        Create a server-sent event.

        :param data: The event data. If it is not a string, it will be
            serialized to JSON using the Flask application's
            :class:`~flask.json.JSONEncoder`.
        :param type: An optional event type.
        :param id: An optional event ID.
        :param retry: An optional integer, to specify the reconnect time for
            disconnected clients of this stream.
        """
        self.data = data
        self.type = type
        self.id = id
        self.retry = retry

    def to_dict(self):
        """
        Serialize this object to a minimal dictionary, for storing in Redis.
        """
        # data is required, all others are optional
        d = {"data": self.data}
        if self.type:
            d["type"] = self.type
        if self.id:
            d["id"] = self.id
        if self.retry:
            d["retry"] = self.retry
        return d

    def __str__(self):
        """
        Serialize this object to a string, according to the `server-sent events
        specification <https://www.w3.org/TR/eventsource/>`_.
        """
        if isinstance(self.data, six.string_types):
            data = self.data
        else:
            data = json.dumps(self.data)
        lines = ["data:{value}".format(value=line) for line in data.splitlines()]
        if self.type:
            lines.insert(0, "event:{value}".format(value=self.type))
        if self.id:
            lines.append("id:{value}".format(value=self.id))
        if self.retry:
            lines.append("retry:{value}".format(value=self.retry))
        return "\n".join(lines) + "\n\n"

    def __repr__(self):
        kwargs = OrderedDict()
        if self.type:
            kwargs["type"] = self.type
        if self.id:
            kwargs["id"] = self.id
        if self.retry:
            kwargs["retry"] = self.retry
        kwargs_repr = "".join(
            ", {key}={value!r}".format(key=key, value=value)
            for key, value in kwargs.items()
        )
        return "{classname}({data!r}{kwargs})".format(
            classname=self.__class__.__name__,
            data=self.data,
            kwargs=kwargs_repr,
        )

    def __eq__(self, other):
        return (
            isinstance(other, self.__class__) and
            self.data == other.data and
            self.type == other.type and
            self.id == other.id and
            self.retry == other.retry
        )


class ServerSentEventsBlueprint(Blueprint):
    """
    A :class:`flask.Blueprint` subclass that knows how to publish, subscribe to,
    and stream server-sent events.
    """
    @property
    def redis(self):
        """
        A :class:`redis.StrictRedis` instance, configured to connect to the
        current application's Redis server.
        """
        redis_url = current_app.config.get("SSE_REDIS_URL")
        if not redis_url:
            redis_url = current_app.config.get("REDIS_URL")
        if not redis_url:
            raise KeyError("Must set a redis connection URL in app config.")
        return redis.StrictRedis.from_url(redis_url)
        # return StrictRedis(connection_pool=pool)

    def publish(self, data, type=None, id=None, retry=None, channel='sse'):
        """
        Publish data as a server-sent event.

        :param data: The event data. If it is not a string, it will be
            serialized to JSON using the Flask application's
            :class:`~flask.json.JSONEncoder`.
        :param type: An optional event type.
        :param id: An optional event ID.
        :param retry: An optional integer, to specify the reconnect time for
            disconnected clients of this stream.
        :param channel: If you want to direct different events to different
            clients, you may specify a channel for this event to go to.
            Only clients listening to the same channel will receive this event.
            Defaults to "sse".
        """
        message = Message(data, type=type, id=id, retry=retry)
        msg_json = json.dumps(message.to_dict())
        return self.redis.publish(channel=channel, message=msg_json)

    def messages(self, channel='sse'):
        """
        A generator of :class:`~flask_sse.Message` objects from the given channel.
        """
        pubsub = self.redis.pubsub()
        pubsub.subscribe(channel)
        for pubsub_message in pubsub.listen():
            logger.info('Voila message: %s' % pubsub_message)
            if pubsub_message['type'] == 'message':
                msg_dict = json.loads(pubsub_message['data'])
                yield Message(**msg_dict)

    def stream(self):
        """
        A view function that streams server-sent events. Ignores any
        :mailheader:`Last-Event-ID` headers in the HTTP request.
        Use a "channel" query parameter to stream events from a different
        channel than the default channel (which is "sse").
        """
        channel = request.args.get('channel') or 'sse'

        @stream_with_context
        def generator():
            for message in self.messages(channel=channel):
                logger.info(message)
                yield str(message)
                logger.info('yielded')

        return current_app.response_class(
            generator(),
            mimetype='text/event-stream',
        )


sse = ServerSentEventsBlueprint('sse', __name__)
"""
An instance of :class:`~flask_sse.ServerSentEventsBlueprint`
that hooks up the :meth:`~flask_sse.ServerSentEventsBlueprint.stream`
method as a view function at the root of the blueprint. If you don't
want to customize this blueprint at all, you can simply import and
use this instance in your application.
"""
sse.add_url_rule(rule="", endpoint="stream", view_func=sse.stream)



# from redis import StrictRedis
# flask_sse = eventlet.import_patched('flask_sse')
# flask_sse.StrictRedis = StrictRedis

# Uncomment for gunicorn
# import flask_sse


app = Flask(__name__)
app.config['REDIS_URL'] = 'redis://127.0.0.1:6379'
# app.register_blueprint(flask_sse.sse, url_prefix='/stream')
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
    sse.publish({"message": "Hello! " + rand()}, type='greeting')
    # flask_sse.sse.publish({"message": "Hello! " + rand()}, type='greeting')
    return "Message sent!"


def main():
    parser = argparse.ArgumentParser(description='HTTP/2 ServerSentEvents server')
    parser.add_argument('-p', dest='port', default=5000, type=int, help='Port')
    args = parser.parse_args()

    listener = eventlet.listen(('0.0.0.0', args.port))
    wsgi.server(listener, app, minimum_chunk_size=1)


if __name__ == "__main__":
    main()


# or run with
# gunicorn test_sse_server:app --worker-class gevent --bind 127.0.0.1:5000

