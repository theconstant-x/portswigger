# authentication_utils.py — shared utilities for Authentication lab automation scripts
#
# Mirrors all prior utils files in structure and naming conventions.
# Import in each lab script with:
#   from authentication_utils import banner, section, make_session, login, ...

import re
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║       PortSwigger — Authentication Lab Automation Suite      ║
║       Enumeration, Brute-Force, 2FA & Logic Flaws            ║
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

    📝 PortSwigger labs use a hidden <input name="csrf"> on all forms
    that modify state. Always fetch the page first before POSTing.
    """
    m = (re.search(r'<input[^>]+name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html) or
         re.search(r'name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html) or
         re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf["\']', html))
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


def load_wordlist(path):
    """
    Read a wordlist file (one entry per line), strip whitespace,
    skip empty lines. Returns a list of strings.
    """
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"  ✘  Wordlist not found: {path}")
        return []


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


def try_login(session, base_url, username, password, xff_ip=None):
    """
    Attempt a single login without following redirects, returning the raw
    response. Used during brute-force loops so callers can inspect status
    codes and response bodies directly.

    xff_ip: if provided, adds an X-Forwarded-For header with this value
    to bypass IP-based rate limiting.
    """
    login_page = session.get(f"{base_url}/login")
    csrf = get_csrf_from_response(login_page.text)

    data = {"username": username, "password": password}
    if csrf:
        data["csrf"] = csrf

    headers = {}
    if xff_ip:
        headers["X-Forwarded-For"] = xff_ip

    return session.post(
        f"{base_url}/login",
        data=data,
        headers=headers,
        allow_redirects=False
    )


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, content):
    """
    Print a clearly bordered block — used for showing leaked data,
    cracked credentials, or exploit payloads.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
