"""
utils.py — shared helpers for the Web Cache Poisoning module labs.

📝 Note: fully request-driven, `requests` handles everything here. The
skill in this module isn't transport tricks — it's the probing
METHODOLOGY (find a cache oracle, find what's unkeyed, find a reflection,
chain them) applied slightly differently per lab.
"""

import time

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
    """Most labs expose X-Cache: hit/miss directly — the main oracle signal."""
    return response.headers.get("X-Cache", "").lower()


def get_cache_key_debug(session, url, **kwargs):
    """
    PortSwigger labs often honor Pragma: x-get-cache-key to show you the
    computed cache key directly in the response — the single fastest way
    to confirm what IS and ISN'T part of it, when the lab supports it.
    """
    headers = kwargs.pop("headers", {}) or {}
    headers["Pragma"] = "x-get-cache-key"
    return session.get(url, headers=headers, **kwargs)


def poison_until_hit(session, url, max_attempts=10, delay=1, **kwargs):
    """
    Repeatedly send the same (poisoning) request until the cache confirms
    a hit — cache timing/expiry means a single send often isn't enough.
    """
    for attempt in range(max_attempts):
        r = session.get(url, **kwargs)
        status = cache_status(r)
        log(f"Attempt {attempt + 1}: X-Cache={status!r}")
        if status == "hit":
            return r
        time.sleep(delay)
    log("Never observed a cache hit within max_attempts.", ok=False)
    return None


CACHE_BUSTER_HEADER_CANDIDATES = ["Origin", "X-Forwarded-Host", "X-Host", "X-Forwarded-Scheme"]
