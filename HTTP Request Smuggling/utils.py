"""
utils.py — shared helpers for the HTTP Request Smuggling module labs.

📝 Note: this module needs byte-level control over raw HTTP requests —
duplicate/conflicting headers, malformed chunk sizes, exact CRLF placement —
that the `requests` library deliberately won't let you send. Everything here
goes over a raw TCP socket instead, tunnelled through Burp via HTTP CONNECT
(same "always through Burp" convention as the rest of the repo, just at the
socket level instead of requests' proxies dict).

⚠️ Timing-based smuggling techniques send requests designed to make the
backend hang waiting for a body that never arrives. Always send a normal
follow-up request afterward to resynchronize the connection/queue before
reusing it — several lab scripts below do this automatically.
"""

import socket
import ssl
import time

from proxies import BURP_PROXIES

BURP_HOST, BURP_PORT = "127.0.0.1", 8080


def log(msg, ok=True):
    prefix = "[+]" if ok else "[-]"
    print(f"{prefix} {msg}")


def note(msg):
    """📝 Educational aside — prints a short explainer inline with exploit output."""
    print(f"📝 {msg}")


def open_tls_via_burp(host, port=443, timeout=15):
    """
    Open a raw socket to `host:port`, tunnelled through Burp's proxy via
    HTTP CONNECT, then TLS-wrap it. Returns the ready-to-use ssl socket.
    """
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


def send_raw(host, raw_request, read_timeout=8, port=443):
    """
    Send a fully custom raw HTTP request (bytes or str, with YOUR OWN exact
    \\r\\n and Content-Length/Transfer-Encoding headers) and return
    (response_bytes, elapsed_seconds). A timeout with no response is itself
    a meaningful signal for CL.TE/TE.CL probing — it isn't necessarily a bug
    in this script.
    """
    if isinstance(raw_request, str):
        raw_request = raw_request.encode()

    tls_sock = open_tls_via_burp(host, port)
    tls_sock.settimeout(read_timeout)

    start = time.time()
    tls_sock.sendall(raw_request)

    response = b""
    try:
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    elapsed = time.time() - start

    tls_sock.close()
    return response, elapsed


def send_two_requests(host, raw_request, follow_up_raw, gap=0, read_timeout=8, port=443):
    """
    Send a (possibly smuggling) request, then a second "victim/normal"
    request on a FRESH connection after `gap` seconds — the standard shape
    for confirming smuggling via differential responses or for capturing
    what a real subsequent request on the shared backend queue sees.
    """
    r1, t1 = send_raw(host, raw_request, read_timeout=read_timeout, port=port)
    if gap:
        time.sleep(gap)
    r2, t2 = send_raw(host, follow_up_raw, read_timeout=read_timeout, port=port)
    return (r1, t1), (r2, t2)


def send_same_connection(host, raw_requests, read_timeout=5, port=443, gap=0):
    """
    Send multiple raw requests back-to-back over the SAME underlying TCP/TLS
    connection (critical for most exploitation labs below — the smuggled
    prefix only lands ahead of a later request if it's reusing the exact
    connection the back-end buffered it on). Returns a list of
    (response_bytes, elapsed) tuples, one per request sent.

    Note: because the smuggling request is often deliberately malformed/
    incomplete from the front-end's point of view, its own "response" may
    be empty, partial, or actually be the START of the next request's
    response — read results with that in mind rather than assuming a clean
    1:1 request/response pairing.
    """
    tls_sock = open_tls_via_burp(host, port)
    tls_sock.settimeout(read_timeout)
    results = []

    for i, raw in enumerate(raw_requests):
        if isinstance(raw, str):
            raw = raw.encode()
        start = time.time()
        tls_sock.sendall(raw)
        if gap and i < len(raw_requests) - 1:
            time.sleep(gap)

        response = b""
        try:
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        results.append((response, time.time() - start))

    tls_sock.close()
    return results


def open_h2_via_burp(host, port=443, timeout=15):
    """
    Open an HTTP/2 connection to `host:port`, tunnelled through Burp via
    CONNECT, with ALPN negotiated to h2. Requires the `h2` package
    (pip install h2 --break-system-packages). Returns (tls_socket, h2.connection.H2Connection).

    ⚠️ The `h2` library validates header values against the HTTP/2 spec and
    will refuse to send an embedded \\r\\n in a header value — which is
    exactly what the CRLF-injection labs (15/16) need. For those two labs,
    this function gets you a legitimate HTTP/2 connection to experiment on,
    but the actual illegal-byte injection step needs Burp's HTTP/2-aware
    raw request editor (Inspector's "Request attributes" / raw hex editing),
    which deliberately bypasses client-side spec validation. Treat those two
    lab scripts as scaffolding + documentation of the payload shape, not a
    fully automated exploit.
    """
    import h2.connection
    import h2.config

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
    ctx.set_alpn_protocols(["h2"])
    tls_sock = ctx.wrap_socket(sock, server_hostname=host)

    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    tls_sock.sendall(conn.data_to_send())

    return tls_sock, conn


def normalize_crlf(raw_template):
    """Allow writing payloads with plain \\n in Python strings, converted to \\r\\n on send."""
    return raw_template.replace("\n", "\r\n")


def summarize_response(response_bytes, label=""):
    text = response_bytes.decode(errors="replace")
    status_line = text.split("\r\n", 1)[0] if text else "(no response)"
    log(f"{label} status line: {status_line!r}")
    return text
