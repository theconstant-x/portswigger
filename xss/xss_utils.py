# xss_utils.py — shared utilities for XSS lab automation scripts
#
# Mirrors sqli_utils.py in structure.
# Import in each lab script with:
#   from xss_utils import banner, section, check_reflection, post_comment, ...

import re
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          PortSwigger — XSS Lab Automation Suite              ║
║          Cross-Site Scripting / Python + requests            ║
╚══════════════════════════════════════════════════════════════╝
""")


def section(title):
    width = 64
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}\n")


def make_session(proxies=None):
    """Return a requests.Session with TLS verification off and optional proxy."""
    s = requests.Session()
    s.verify = False
    if proxies:
        s.proxies = proxies
    return s


def check_reflection(response_text, payload, label="Payload"):
    """
    Check whether the raw (un-encoded) payload string is present in the HTTP
    response body.

    ⚠  This confirms server-side reflection only.
       JavaScript execution requires a real browser — requests cannot run JS.
       For DOM-based XSS labs, a raw reflection here means the value reaches
       the client intact; the sink (document.write, innerHTML, etc.) then
       executes it when a browser renders the page.
    """
    if payload in response_text:
        print(f"  ✔  {label} reflected raw in response → XSS fires in a browser")
        return True
    print(f"  ✘  {label} NOT found raw — may be encoded or filtered")
    return False


def get_csrf(session, url):
    """
    Fetch a page and extract the CSRF token from a hidden form input.
    Returns the token string, or None if not found.
    """
    r = session.get(url)
    # Try both attribute orderings that PortSwigger uses
    m = (re.search(r'<input[^>]+name="csrf"[^>]+value="([^"]+)"', r.text) or
         re.search(r'name="csrf"\s+value="([^"]+)"', r.text))
    if m:
        return m.group(1)
    print("  ✘  CSRF token not found on page")
    return None


def post_comment(session, base_url, post_id, comment,
                 name="Attacker", email="a@b.com", website=""):
    """
    Submit a blog post comment.

    Fetches the CSRF token from the post page automatically, then POSTs
    the comment to /post/comment. Returns the response, or None on failure.

    Parameters
    ----------
    session   : requests.Session
    base_url  : lab root URL (no trailing slash)
    post_id   : integer post ID (usually 1)
    comment   : the comment body — this is where your XSS payload goes
    name      : display name shown under the comment
    email     : required by the form but not rendered to other users
    website   : optional — used in href-injection labs (labs 08, 23)
    """
    csrf = get_csrf(session, f"{base_url}/post?postId={post_id}")
    if not csrf:
        return None
    data = {
        "csrf":    csrf,
        "postId":  str(post_id),
        "comment": comment,
        "name":    name,
        "email":   email,
        "website": website,
    }
    r = session.post(f"{base_url}/post/comment", data=data, allow_redirects=True)
    return r


def verify_stored(session, base_url, post_id, payload, label="Payload"):
    """
    Fetch a blog post page and confirm the stored payload is present raw.
    Calls check_reflection internally.
    """
    r = session.get(f"{base_url}/post?postId={post_id}")
    return check_reflection(r.text, payload, label)


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, code):
    """
    Print a clearly bordered block containing an exploit payload or script.
    Used for labs that require the exploit server or manual browser steps.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in code.strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
