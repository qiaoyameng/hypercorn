.. _tunnels:

CONNECT tunnels
===============

Hypercorn supports an opt-in ASGI tunnel extension for ``CONNECT``
requests. This allows an app to act as a gateway (e.g. a proxy)
where the app itself decides which targets to allow and which to
reject — Hypercorn never connects to any target itself.

The extension is available over HTTP/1.1 (where accepting switches
the whole connection to the tunnel) and HTTP/2 (where only the
single stream is used, leaving other streams unaffected).

The scope
---------

A ``CONNECT`` request results in a ``tunnel`` scope, with the
request target (usually ``host:port``) as the ``path``,

.. code-block:: python

    {
        "type": "tunnel",
        "asgi": {"spec_version": "2.5", "version": "3.0"},
        "http_version": "2",
        "method": "CONNECT",
        "scheme": "https",
        "path": "example.com:443",
        "raw_path": b"example.com:443",
        "query_string": b"",
        "root_path": "",
        "headers": [...],
        "client": ("127.0.0.1", 5000),
        "server": ("127.0.0.1", 443),
        "extensions": {"tunnel.http.response": {}},
    }

Receiving events
----------------

The first event is ``tunnel.connect`` after which the app must
either accept or reject the tunnel. Once accepted raw byte data is
received via ``tunnel.receive`` events,

.. code-block:: python

    {"type": "tunnel.receive", "bytes": b"data", "more": True}

If the client half-closes the tunnel (closes only its sending side)
a final ``tunnel.receive`` event with ``more`` set to ``False`` is
sent. The app may continue to send its own data, nothing the client
has yet to receive is discarded. A ``tunnel.disconnect`` event is
sent if the connection is lost.

Sending events
--------------

To accept the tunnel send ``tunnel.accept`` (a ``200`` response is
sent to the client), afterwards raw bytes are sent via
``tunnel.send`` events and the tunnel is closed via
``tunnel.close``,

.. code-block:: python

    await send({"type": "tunnel.accept", "headers": []})
    await send({"type": "tunnel.send", "bytes": b"data"})
    await send({"type": "tunnel.close"})

To reject the tunnel send a normal HTTP response instead, via the
``tunnel.http.response`` extension,

.. code-block:: python

    await send({"type": "tunnel.http.response.start", "status": 403, "headers": []})
    await send({"type": "tunnel.http.response.body", "body": b"Forbidden"})

HTTP response messages are only valid before the tunnel is accepted,
after acceptance only raw byte messages (``tunnel.send``) are
allowed.
