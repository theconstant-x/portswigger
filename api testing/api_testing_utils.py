# api_testing_utils.py — shared utilities for API Testing lab automation scripts
#
# Mirrors sqli_utils.py, xss_utils.py, csrf_utils.py, and access_control_utils.py.
# Import in each lab script with:
#   from api_testing_utils import banner, section, make_session, login, ...

import re
import json
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        PortSwigger — API Testing Lab Automation Suite        ║
║        Recon, Mass Assignment & Parameter Pollution          ║
╚══════════════════════════════════════════════════════════════╝
""")


def section(title):
    width = 64
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}\n")


def make_session(proxies=None):
    """
    Return a requests.Session with TLS verification disabled and optional proxy.

    TLS verification is disabled because Burp Suite uses a self-signed
    certificate for its HTTPS interception proxy.
    """
    s = requests.Session()
    s.verify = False
    if proxies:
        s.proxies = proxies
    return s


def get_csrf_from_response(html):
    """
    Extract a CSRF token from an HTML page's hidden form input.
    Returns the token string or None if not found.
    """
    m = (re.search(r'<input[^>]+name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html) or
         re.search(r'name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html))
    return m.group(1) if m else None


def login(session, base_url, username="wiener", password="peter"):
    """
    Log in to the PortSwigger lab with the provided credentials.
    Returns True on success, False on failure.
    """
    login_page = session.get(f"{base_url}/login")
    csrf = get_csrf_from_response(login_page.text)

    data = {"username": username, "password": password}
    if csrf:
        data["csrf"] = csrf

    r = session.post(f"{base_url}/login", data=data, allow_redirects=True)

    if "Log out" in r.text or "My account" in r.text:
        print(f"  ✔  Logged in as {username}")
        return True

    print(f"  ✘  Login failed for {username} (status {r.status_code})")
    return False


def check_status(response, expected, label="Request"):
    """
    Compare response.status_code against an expected value (int or list of
    ints) and print a pass/fail line.
    """
    expected_list = expected if isinstance(expected, (list, tuple)) else [expected]
    if response.status_code in expected_list:
        print(f"  ✔  {label} → status {response.status_code} (as expected)")
        return True
    print(f"  ✘  {label} → status {response.status_code} (expected {expected_list})")
    return False


def pretty_json(response_or_text):
    """
    Try to parse and pretty-print JSON from a response object or raw string.
    Falls back to printing raw text if parsing fails.
    """
    text = response_or_text.text if hasattr(response_or_text, "text") else response_or_text
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2)
    except (json.JSONDecodeError, TypeError):
        return text


def find_product_id(session, base_url, name_fragment="l33t"):
    """
    Scan the home page for a product link whose text or URL contains the
    given fragment (default: the 'l33t' leather jacket used across several
    API Testing labs). Returns the productId as a string, or '1' as a
    reasonable fallback if not found.
    """
    r = session.get(base_url)
    matches = re.findall(
        r'/product\?productId=(\d+)[^"\']*"[^>]*>[^<]*' + re.escape(name_fragment),
        r.text, re.IGNORECASE
    )
    if not matches:
        # Looser fallback: any productId near the fragment text
        idx = r.text.lower().find(name_fragment.lower())
        if idx != -1:
            window = r.text[max(0, idx - 300):idx + 50]
            pid_match = re.search(r'productId=(\d+)', window)
            if pid_match:
                matches = [pid_match.group(1)]

    if matches:
        print(f"  ✔  Found product ID via page scan: {matches[0]}")
        return matches[0]

    print("  ?  Could not auto-detect product ID — falling back to '1'")
    return "1"


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, content):
    """
    Print a clearly bordered block — used for showing raw HTTP responses,
    leaked tokens, JSON bodies, or exploit details.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
