# access_control_utils.py — shared utilities for Access Control lab automation scripts
#
# Import in each lab script with:
#   from access_control_utils import banner, section, make_session, login, ...

import re
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║      PortSwigger — Access Control Lab Automation Suite       ║
║      Broken Access Control & Privilege Escalation            ║
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

    Most Access Control labs provide wiener:peter as the low-privilege
    test account, and administrator:admin where an admin account exists
    for familiarisation.

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


def fetch(session, url, method="GET", **kwargs):
    """
    Generic request wrapper that prints the method and URL before sending.
    Returns the response object.
    """
    print(f"  ➜  {method} {url}")
    return session.request(method, url, allow_redirects=kwargs.pop("allow_redirects", True), **kwargs)


def check_status(response, expected, label="Request"):
    """
    Compare response.status_code against an expected value (int or list of ints)
    and print a pass/fail line.
    """
    expected_list = expected if isinstance(expected, (list, tuple)) else [expected]
    if response.status_code in expected_list:
        print(f"  ✔  {label} → status {response.status_code} (as expected)")
        return True
    print(f"  ✘  {label} → status {response.status_code} (expected {expected_list})")
    return False


def check_contains(response_text, needle, label="Content"):
    """Check whether a string is present in a response body."""
    if needle in response_text:
        print(f"  ✔  {label} found in response")
        return True
    print(f"  ✘  {label} NOT found in response")
    return False


def extract_between(text, start_marker, end_marker):
    """
    Extract and return the substring between two markers.
    Returns None if either marker is not found.

    Useful for pulling values like API keys or passwords out of raw HTML
    where a precise regex isn't worth writing for a one-off lab.
    """
    start_idx = text.find(start_marker)
    if start_idx == -1:
        return None
    start_idx += len(start_marker)
    end_idx = text.find(end_marker, start_idx)
    if end_idx == -1:
        return None
    return text[start_idx:end_idx].strip()


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, content):
    """
    Print a clearly bordered block — used for showing raw HTTP responses,
    leaked secrets, or exploit payloads.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in content.strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
