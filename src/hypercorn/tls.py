from __future__ import annotations

from dataclasses import dataclass
from ssl import SSLContext, SSLObject, SSLSocket
from time import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config


@dataclass
class TLSReloadResult:
    """The observable outcome of a TLS reload attempt.

    ``success`` is True only if the new context was constructed,
    validated, and swapped in. On failure ``error`` describes why and
    the previous context remains in use.
    """

    success: bool
    error: str | None = None
    reloaded_at: float | None = None

    def __bool__(self) -> bool:
        return self.success


class TLSReloader:
    """Manages the TLS contexts used by the listeners of a single worker.

    The listeners are handed the stable :attr:`dispatcher` context,
    which routes every new handshake (via an SNI callback) to the
    currently active context. Reloading therefore only requires
    building and validating a candidate context and then atomically
    swapping a single reference:

    * Established connections are unaffected, as they keep the context
      they were established with.
    * A new connection always completes a full handshake with either
      the old or the new context, never a mixture.
    * If the candidate cannot be built (files missing, certificate and
      key mismatch, ...) the previous context stays active and a
      failure :class:`TLSReloadResult` is returned.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self._current: SSLContext | None = None
        self._dispatcher: SSLContext | None = None
        self.last_result: TLSReloadResult | None = None

    @property
    def context(self) -> SSLContext:
        """The currently active TLS context."""
        if self._current is None:
            self._current = self._build_context()
        return self._current

    @property
    def dispatcher(self) -> SSLContext:
        """The stable context the listeners should use.

        Handshakes that include SNI are routed to the active context,
        handshakes without SNI are served by this context directly
        (which is kept in sync on every successful reload).
        """
        if self._dispatcher is None:
            self._dispatcher = self._build_context()
            self._dispatcher.set_servername_callback(self._route_handshake)
        return self._dispatcher

    def reload(self) -> TLSReloadResult:
        """Re-read the TLS configuration and swap the active context.

        The candidate context is fully constructed and validated
        (including the certificate/private key match) before the
        switch, so any failure leaves the previous context in place.
        """
        try:
            candidate = self._build_context()
        except (OSError, ValueError) as error:
            # OSError covers missing/unreadable files and ssl.SSLError
            # (e.g. certificate/key mismatch), ValueError covers
            # invalid configuration values.
            result = TLSReloadResult(success=False, error=str(error))
        else:
            self._current = candidate
            self._sync_dispatcher()
            result = TLSReloadResult(success=True, reloaded_at=time())
        self.last_result = result
        return result

    def _build_context(self) -> SSLContext:
        context = self.config.create_ssl_context()
        if context is None:
            raise ValueError("TLS is not enabled, certfile and keyfile must be configured")
        return context

    def _route_handshake(
        self, sslobj: SSLSocket | SSLObject, server_name: str | None, initial_context: SSLContext
    ) -> None:
        # A single atomic reference load, hence the handshake
        # completes with a consistent (old or new) context.
        sslobj.context = self.context

    def _sync_dispatcher(self) -> None:
        # Keep the dispatcher in step with the configuration so that
        # handshakes without SNI also see the reloaded certificate,
        # ALPN protocols, and verification settings.
        config = self.config
        dispatcher = self._dispatcher
        if dispatcher is None:
            return
        dispatcher.set_ciphers(config.ciphers)
        dispatcher.set_alpn_protocols(config.alpn_protocols)
        if config.certfile is not None and config.keyfile is not None:
            dispatcher.load_cert_chain(
                certfile=config.certfile,
                keyfile=config.keyfile,
                password=config.keyfile_password,
            )
        if config.ca_certs is not None:
            dispatcher.load_verify_locations(config.ca_certs)
        if config.verify_mode is not None:
            dispatcher.verify_mode = config.verify_mode
        if config.verify_flags is not None:
            dispatcher.verify_flags = config.verify_flags
