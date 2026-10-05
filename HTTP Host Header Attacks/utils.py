"""
utils.py — shared helpers for the HTTP Host Header Attacks module labs.

📝 Note: `requests` normally derives the Host header from the URL you pass
it and won't let you easily send a MISMATCHED one (URL says one host, Host
header says another) through its normal API. We work around this by
connecting directly to the lab's real IP/hostname but overriding the Host
header explicitly — `requests` does respect an explicit Host header you set
yourself, it just won't use it for TLS SNI/connection routing, which is
exactly the scenario these labs are testing anyway (the app sees our Host
header value; our TCP connection still goes to the real target IP).
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


def request_with_host(session, method, url, host_header, **kwargs):
    """
    Send a request to `url` but with the Host header overridden to
    `host_header` — the core primitive this whole module is built on.
    """
    headers = kwargs.pop("headers", {}) or {}
    headers["Host"] = host_header
    return session.request(method, url, headers=headers, **kwargs)


def probe_host_header_reflection(session, target, test_host="example-attacker-host.com"):
    """
    Quick check: does an arbitrary Host header value get reflected anywhere
    in the response (absolute URLs, a canonical link tag, password-reset-
    style content)? A strong first signal for exploitability.
    """
    r = request_with_host(session, "GET", target, test_host)
    reflected = test_host in r.text
    log(f"Host header {test_host!r} reflected in response: {reflected}", ok=reflected)
    return r, reflected
