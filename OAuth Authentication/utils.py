"""
utils.py — shared helpers for the OAuth Authentication module labs.

📝 Note: OAuth labs differ from most other modules in one key way — there
are usually TWO hosts involved: the client application (the "blog" site
you log into) and the OAuth service itself (the social-login provider).
Keep both base URLs handy; several exploits involve crafting a URL on
one host that gets sent to the other.
"""

import base64
import json
import re

import requests

from proxies import BURP_PROXIES, VERIFY_SSL


def get_session():
    """A requests.Session pre-wired to go through Burp."""
    s = requests.Session()
    s.proxies.update(BURP_PROXIES)
    s.verify = VERIFY_SSL
    return s


def log(msg, ok=True):
    """Small consistent status printer, matching the rest of the repo."""
    prefix = "[+]" if ok else "[-]"
    print(f"{prefix} {msg}")


def note(msg):
    """📝 Educational aside — prints a short explainer inline with exploit output."""
    print(f"📝 {msg}")


def extract_csrf_token(html, field_name="csrf"):
    """Pull a hidden CSRF token out of a login/account form."""
    match = re.search(rf'name="{field_name}"\s+value="([^"]+)"', html)
    return match.group(1) if match else None


def decode_jwt(token):
    """
    Decode a JWT's header and payload without verifying the signature.
    Useful for inspecting access tokens / id_tokens the OAuth service hands back.
    Returns (header_dict, payload_dict) or (None, None) if it doesn't look like a JWT.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return None, None

    def _b64decode(segment):
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))

    try:
        header = _b64decode(parts[0])
        payload = _b64decode(parts[1])
        return header, payload
    except Exception:
        return None, None


def extract_fragment_params(location_header):
    """
    OAuth implicit-flow redirects carry the access_token etc. in the URL
    fragment (after #), which requests/burp show you in the Location header
    but which browsers never send back to a server. Parse it out manually.
    """
    if "#" not in location_header:
        return {}
    fragment = location_header.split("#", 1)[1]
    params = {}
    for pair in fragment.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v
    return params


def check_lab_solved(session, target_base, indicator_path="/", indicator_text="Congratulations"):
    """Generic 'did we solve it' check — most labs flag success on the home page banner."""
    r = session.get(f"{target_base}{indicator_path}")
    solved = indicator_text in r.text
    log("Lab solved!" if solved else "Not solved yet.", ok=solved)
    return solved
