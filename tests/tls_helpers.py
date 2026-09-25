from __future__ import annotations

import hashlib
import socket
import ssl
from pathlib import Path

ASSETS_PATH = Path(__file__).parent / "assets"

CA_PATH = ASSETS_PATH / "tls_ca.pem"
CERT_A_PATH = ASSETS_PATH / "tls_a_cert.pem"
KEY_A_PATH = ASSETS_PATH / "tls_a_key.pem"
CERT_B_PATH = ASSETS_PATH / "tls_b_cert.pem"
KEY_B_PATH = ASSETS_PATH / "tls_b_key.pem"
CLIENT_CERT_PATH = ASSETS_PATH / "tls_client_cert.pem"
CLIENT_KEY_PATH = ASSETS_PATH / "tls_client_key.pem"

RESPONSE_BODY = b"Hello TLS"


async def tls_app(scope, receive, send) -> None:  # type: ignore[no-untyped-def]
    if scope["type"] == "lifespan":
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif event["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    else:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", str(len(RESPONSE_BODY)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": RESPONSE_BODY})


def client_context(
    *, alpn: list[str] | None = None, with_client_cert: bool = False, sni: bool = True
) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(CA_PATH))
    if alpn is not None:
        context.set_alpn_protocols(alpn)
    if with_client_cert:
        context.load_cert_chain(str(CLIENT_CERT_PATH), str(CLIENT_KEY_PATH))
    if not sni:
        # SNI is only sent if a server hostname is given, which
        # conflicts with hostname checking
        context.check_hostname = False
    return context


def connect(
    port: int,
    *,
    server_hostname: str | None = "localhost",
    alpn: list[str] | None = None,
    with_client_cert: bool = False,
) -> ssl.SSLSocket:
    context = client_context(
        alpn=alpn, with_client_cert=with_client_cert, sni=server_hostname is not None
    )
    raw_socket = socket.create_connection(("127.0.0.1", port))
    return context.wrap_socket(raw_socket, server_hostname=server_hostname)


def fingerprint(sock: ssl.SSLSocket) -> str:
    return hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()


def http1_get(sock: ssl.SSLSocket) -> bytes:
    sock.sendall(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if chunk == b"":
            raise ConnectionError("Connection closed whilst reading headers")
        response += chunk
    raw_headers, body = response.split(b"\r\n\r\n", 1)
    content_length = 0
    for line in raw_headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if chunk == b"":
            raise ConnectionError("Connection closed whilst reading body")
        body += chunk
    return body
