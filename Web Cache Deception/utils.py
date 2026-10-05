"""
utils.py — shared helpers for the Web Cache Deception module labs.

📝 Note: fully request-driven. Unlike Web Cache Poisoning (injecting
malicious unkeyed INPUT), deception is about exploiting URL PATH parsing
discrepancies between cache and origin — getting the cache to treat a
dynamic, sensitive page as if it were a static file. No payload injection
at all in most of these; just path crafting.
"""

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


def cache_status(response):
    return response.headers.get("X-Cache", "").lower()


# PortSwigger's own published candidate delimiter list for this module —
# characters that might be treated as a path separator by one parser
# (cache or origin) but not the other.
DELIMITER_CANDIDATES = [
    ";", "#", "?", "%23", "%3f", "%00", "%0a", "%09", "%2f", "%5c",
    ".", ",", "!", "~", "*", "'", "(", ")",
]


def probe_delimiters(session, base_path, suffix="abc", candidates=None):
    """
    For each candidate delimiter, request base_path + delimiter + suffix
    and report status — used to find which characters the ORIGIN server
    treats as "end of path" (ignoring everything after) vs which it
    doesn't. A 200 (same as the clean base_path) suggests the origin
    stops parsing at that delimiter; an error suggests it doesn't.
    """
    candidates = candidates or DELIMITER_CANDIDATES
    results = {}
    for d in candidates:
        url = f"{base_path}{d}{suffix}"
        r = session.get(url)
        results[d] = r.status_code
        log(f"{d!r:8} -> status {r.status_code}")
    return results
