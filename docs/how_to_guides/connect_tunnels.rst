.. _connect_tunnels:

CONNECT tunnels (``http.connect`` extension)
============================================

Hypercorn supports an opt-in ASGI extension, ``http.connect``, that
allows an application to decide per CONNECT request whether to
establish a tunnel. It is available for HTTP/1.1 connections (the
connection switches to a raw tunnel) and for individual HTTP/2
streams. Hypercorn does not connect to the requested target itself —
the application owns the target choice and any authorisation.

CONNECT requests are delivered to the app as a normal ``http`` scope
with the ``http.connect`` extension advertised,

.. code-block:: python

    if scope["method"] == "CONNECT" and "http.connect" in scope["extensions"]:
        ...

Before accepting, the app may send an ordinary HTTP response
(``http.response.start`` / ``http.response.body``) to reject the
request. To establish the tunnel the app instead sends
``http.connect.accept`` with an optional 2XX ``status`` (default 200)
and ``headers``. After acceptance HTTP body framing no longer applies
and raw bytes flow in both directions,

.. code-block:: python

    await send({"type": "http.connect.accept", "status": 200, "headers": []})
    while True:
        event = await receive()
        if event["type"] == "http.connect.receive":
            # event["body"] are raw bytes from the client,
            # event["more_body"] is False once the client half-closes
            await send(
                {
                    "type": "http.connect.send",
                    "body": event["body"],
                    "more_body": event["more_body"],
                }
            )
            if not event["more_body"]:
                break
        elif event["type"] == "http.disconnect":
            break

A client half-close (TCP FIN for HTTP/1.1, ``END_STREAM`` for HTTP/2)
only closes the client to server direction — the app receives
``http.connect.receive`` with ``more_body`` set to ``False`` and may
continue sending. Likewise sending ``http.connect.send`` with
``more_body`` set to ``False`` half-closes only the server to client
direction.
