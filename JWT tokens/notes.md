# JWT Attacks

PortSwigger Web Security Academy module: [JWT attacks](https://portswigger.net/web-security/jwt)

## 📝 Core concepts

- **Structure:** `header.payload.signature`, each segment base64url-encoded JSON
  (signature is raw bytes). Header carries `alg` (and sometimes `jwk`/`jku`/`kid`) —
  anything in the header is attacker-controlled input that the server trusts
  *before* it has verified anything.
- **The signature is the only thing stopping tampering.** If the server never
  actually checks it (or checks it wrong), the payload is just a JSON blob
  you can edit freely — e.g. flip `"role": "user"` → `"admin"`.
- **`alg: none`** — some libraries treat this as "no signature required." Strip
  the signature entirely and some servers still accept it.
- **Algorithm confusion (RS256 → HS256)** — if the server's verification code
  does `verify(token, key, algorithms=["RS256","HS256"])` without pinning the
  algorithm, you can take the server's own PUBLIC key (often exposed, e.g. via
  `/jwks.json`) and use it as the HMAC secret to self-sign a token the server
  will accept as genuinely RS256-verified.
- **`jwk` header injection** — some servers accept a `jwk` embedded directly in
  the token's own header as the trusted verification key. Generate your own
  keypair, sign with your private key, embed your public key as the `jwk`.
- **`jku` header injection** — similar, but the header points to a URL hosting
  a JWK Set. If the server fetches whatever URL you give it, host your own.
- **`kid` (key ID) header** — identifies which key to use, often as a filename
  or DB lookup. Path traversal (`kid: ../../dev/null`) or SQL injection in the
  lookup can force a predictable/empty/attacker-known key.
- **Weak/guessable HMAC secrets** are brute-forceable offline once you have
  one valid token to test guesses against — no network round-trips needed.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature) | Apprentice | ⬜ |
| 2 | [JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification) | Apprentice | ⬜ |
| 3 | [JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key) | Practitioner | ⬜ |
| 4 | [JWT authentication bypass via jwk header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection) | Practitioner | ⬜ |
| 5 | [JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection) | Practitioner | ⬜ |
| 6 | [JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal) | Practitioner | ⬜ |
| 7 | [JWT authentication bypass via algorithm confusion](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-algorithm-confusion) | Expert | ⬜ |
| 8 | [JWT authentication bypass via algorithm confusion with no exposed key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Unverified signature
📝 Server decodes the JWT but never calls a verify step at all. Edit the
payload's `sub` claim to `admin`, re-encode, drop any signature — accepted.

### Lab 2 — Flawed signature verification
📝 Server DOES call a verify function, but it's something like "does a
signature exist" rather than "is it cryptographically valid" — or it checks
`alg` from the header and honors `none` as a legitimate choice.

### Lab 3 — Weak signing key
📝 The HMAC secret is guessable — short, dictionary word, or default. Brute
force offline against a wordlist (e.g. `jwt-secrets.txt` from SecLists), then
forge any payload you like.

### Lab 4 — jwk header injection
📝 Generate an RSA keypair. Sign a forged token with your private key, and
embed your public key directly in the token's `jwk` header. Server trusts
whatever key the token says to verify itself against.

### Lab 5 — jku header injection
📝 Same idea, but point `jku` at a JWK Set URL you control (host on the
exploit server) instead of embedding the key inline.

### Lab 6 — kid header path traversal
📝 `kid` is used to build a filesystem path to the signing key. Point it at a
predictable file with known/empty content (`../../../../dev/null`) and sign
with that as the HMAC key (empty bytes).

### Lab 7 — Algorithm confusion
📝 Fetch the server's RSA public key (often at `/jwks.json`). Use its exact
bytes as an HMAC-SHA256 secret to self-sign a forged token with `alg: HS256`.
If verification doesn't pin the algorithm, it accepts your HMAC signature as
if it were a valid RSA one.

### Lab 8 — Algorithm confusion, no exposed public key
📝 No `/jwks.json` this time — have to derive/reconstruct the public key
yourself from two valid tokens signed with the same RSA key (tools like
`jwt_forgery.py` from the `rsa_sign2n` project automate the modulus
recovery), then proceed as in Lab 7.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
