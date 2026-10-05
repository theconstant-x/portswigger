"""
utils.py — shared helpers for the Essential Skills module scaffold.

⚠️ See notes.md — this module's exact lab content is UNCONFIRMED. These
helpers are generic request/encoding utilities likely to be relevant
regardless of what the real labs turn out to test, since both plausible
candidates (Repeater-style request tweaking, Decoder/Intruder-style
encoding and brute-forcing) reduce to the same underlying primitives used
throughout the rest of this repo.
"""

import base64
import urllib.parse

from proxies import BURP_PROXIES, VERIFY_SSL
import requests


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


# ---- Decoder-equivalent helpers ---------------------------------------

def try_all_decodings(value):
    """
    Burp Decoder's "smart decode" equivalent — try the common encodings
    against a captured value and report which ones produce plausible
    (printable) output, rather than assuming you already know the format.
    """
    results = {}

    try:
        results["base64"] = base64.b64decode(value + "=" * (-len(value) % 4)).decode(errors="replace")
    except Exception as e:
        results["base64"] = f"(failed: {e})"

    try:
        results["url"] = urllib.parse.unquote(value)
    except Exception as e:
        results["url"] = f"(failed: {e})"

    try:
        results["hex"] = bytes.fromhex(value).decode(errors="replace")
    except Exception as e:
        results["hex"] = f"(failed: {e})"

    for encoding, decoded in results.items():
        log(f"{encoding:8} -> {decoded!r}")
    return results


# ---- Intruder-equivalent helper ----------------------------------------

def sweep_payloads(session, url, param_name, payloads, method="GET", other_data=None,
                    success_marker=None):
    """
    Burp Intruder's "sniper" attack equivalent — sweep a list of candidate
    values through one parameter, flagging responses that match a given
    success marker (a status code, or a substring in the response body).
    """
    for payload in payloads:
        data = dict(other_data or {})
        data[param_name] = payload
        if method.upper() == "GET":
            r = session.get(url, params=data)
        else:
            r = session.post(url, data=data)

        hit = False
        if success_marker:
            if isinstance(success_marker, int):
                hit = r.status_code == success_marker
            else:
                hit = success_marker in r.text

        log(f"{payload!r:30} -> status {r.status_code}{' [MATCH]' if hit else ''}", ok=hit)
        if hit:
            return payload, r
    return None, None
