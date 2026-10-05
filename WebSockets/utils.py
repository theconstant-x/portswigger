"""
utils.py — shared helpers for the WebSockets module labs.

📝 Note: WebSocket connections start as a normal HTTP request (the
"handshake", an Upgrade: websocket request) that gets switched to a raw
framed-message protocol once the server replies 101. We implement the
handshake + minimal frame encode/decode ourselves over a raw socket
(tunnelled through Burp, same CONNECT pattern as the smuggling module)
rather than using a full WebSocket client library — that way we keep full
control over the handshake's headers for Lab 2, and can still send/receive
plain messages for Labs 1 and 3.
"""

import base64
import hashlib
import os
import socket
import ssl
import struct

from proxies import BURP_PROXIES

BURP_HOST, BURP_PORT = "127.0.0.1", 8080
WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def log(msg, ok=True):
    prefix = "[+]" if ok else "[-]"
    print(f"{prefix} {msg}")


def note(msg):
    """📝 Educational aside — prints a short explainer inline with exploit output."""
    print(f"📝 {msg}")


def _open_tls_via_burp(host, port=443, timeout=15):
    sock = socket.create_connection((BURP_HOST, BURP_PORT), timeout=timeout)
    connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    sock.sendall(connect_req.encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    if b"200" not in response.split(b"\r\n", 1)[0]:
        raise ConnectionError(f"CONNECT via Burp failed: {response[:200]!r}")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=host)


def ws_handshake(host, path, cookie=None, extra_headers=None, origin=None, port=443):
    """
    Perform the WebSocket opening handshake over a raw socket (via Burp).
    Returns the connected socket on success (101), or raises on failure —
    the response text is included in the exception for easy debugging.
    """
    sock = _open_tls_via_burp(host, port)
    sock.settimeout(10)

    key = base64.b64encode(os.urandom(16)).decode()

    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin is not None:
        headers.append(f"Origin: {origin}")
    if cookie:
        headers.append(f"Cookie: {cookie}")
    if extra_headers:
        headers.extend(extra_headers)

    request = "\r\n".join(headers) + "\r\n\r\n"
    sock.sendall(request.encode())

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
    if "101" not in status_line:
        raise ConnectionError(f"Handshake failed: {status_line} | {response[:400]!r}")

    return sock, response.decode(errors="replace")


def send_ws_text(sock, message):
    """
    Encode and send a text frame. Client-to-server frames MUST be masked
    per RFC 6455 — we do that here with a random 4-byte mask key.
    """
    payload = message.encode()
    mask_key = os.urandom(4)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    length = len(payload)
    if length <= 125:
        header = struct.pack("!BB", 0x81, 0x80 | length)
    elif length <= 65535:
        header = struct.pack("!BBH", 0x81, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x81, 0x80 | 127, length)

    sock.sendall(header + mask_key + masked)


def recv_ws_text(sock, timeout=5):
    """Read and decode a single (unmasked, server-to-client) text frame."""
    sock.settimeout(timeout)
    try:
        first2 = sock.recv(2)
        if len(first2) < 2:
            return None
        b1, b2 = first2[0], first2[1]
        length = b2 & 0x7F

        if length == 126:
            length = struct.unpack("!H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", sock.recv(8))[0]

        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                break
            payload += chunk
        return payload.decode(errors="replace")
    except socket.timeout:
        return None
