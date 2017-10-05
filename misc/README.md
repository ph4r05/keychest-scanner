# Misc files for KeyChest Scanner

- Util scripts
- PoC scripts
- HTTP/2 ServerSentEvents tests
- Socket.io tests

## Flask-sse does not work with `eventlet`

- Run server `python test_sse_server.py` (direct runs uses eventlet)
- Run the client `python test_sse_client.py`
- Try accessing normal page provided by the Flask `http://127.0.0.1:5000/` - server is busy.
- Try sending hello event `http://127.0.0.1:5000/hello` - server is busy.
- Under normal operation sending hello should do something to the main page.

Observations:

- The problem is with `redis.StrictRedis` running on the `eventlet`. If patched, program is communicating with Redis properly.
- The problem is yield does not propagate to the stream user.

Solution

```
wsgi.server(listener, app, minimum_chunk_size=1)
```

