#!/bin/bash
gunicorn test_sse_server:app --worker-class gevent --bind 127.0.0.1:5000
