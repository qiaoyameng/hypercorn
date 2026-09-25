=============
TLS reloading
=============

Hypercorn can reload the TLS configuration (certificate, key, CA
certs, ALPN protocols, and verification settings) without restarting
the server. This allows certificates to be rotated whilst
established connections continue to work, and new connections
complete a full handshake with either the old or the new certificate.

To reload, replace the certificate/key files and call
:meth:`hypercorn.config.Config.reload_tls` on the config the worker
is serving with,

.. code-block:: python

    result = config.reload_tls()
    if not result.success:
        print(f"TLS reload failed: {result.error}")

The reload first constructs and validates a candidate context
(re-reading the certfile, keyfile, CA certs, and related
configuration) and only then swaps the context the listeners use. If
the files are missing or the certificate and key do not match, the
reload fails and the previous certificate remains in use. The most
recent :class:`hypercorn.tls.TLSReloadResult` is also available as
``config.tls_reloader.last_result``.

.. note::

    With multiple workers each worker process holds its own TLS
    contexts, so the reload must be triggered in each worker process.
    QUIC (HTTP/3) sockets are not affected by the reload.
