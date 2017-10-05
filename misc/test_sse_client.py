#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import pprint
import sseclient
import argparse


def with_urllib3(url):
    """Get a streaming response for the given event feed using urllib3."""
    import urllib3
    http = urllib3.PoolManager()
    return http.request('GET', url, preload_content=False)


def with_requests(url):
    """Get a streaming response for the given event feed using requests."""
    import requests
    return requests.get(url, stream=True)


parser = argparse.ArgumentParser(description='HTTP/2 ServerSentEvents')
parser.add_argument('-H', dest='host', default='127.0.0.1', help='Host to connect to')
parser.add_argument('-p', dest='port', default='5000', help='Port')
parser.add_argument('-r', dest='requests', default=False, action='store_const', const=True, help='Use requests library')
args = parser.parse_args()

url = 'http://%s:%s/stream' % (args.host, args.port)
response = with_requests(url) if args.requests else with_urllib3(url)
client = sseclient.SSEClient(response)
for event in client.events():
    pprint.pprint(json.loads(event.data))


