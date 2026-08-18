# os_command_injection_utils.py — shared utilities for OS Command Injection
# lab automation scripts
#
# Mirrors all prior utils files in structure and naming conventions.
# Import in each lab script with:
#   from os_command_injection_utils import banner, section, make_session, ...

import re
import time
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║    PortSwigger — OS Command Injection Lab Automation Suite   ║
║    Visible, Blind, Redirection & Out-of-Band Techniques      ║
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


def timed_request(method_func, *args, **kwargs):
    """
    Call any requests method (session.get, session.post, etc.), returning
    a tuple of (response, elapsed_seconds). Used for time-delay based
    blind command injection confirmation.
    """
    start = time.time()
    response = method_func(*args, **kwargs)
    elapsed = time.time() - start
    return response, elapsed


def submit_feedback(session, base_url, email, name="test", subject="test", message="test"):
    """
    Submit the feedback form used across the blind OS command injection
    labs. Fetches a fresh CSRF token first. Returns the response.

    The 'email' parameter is where the injection payload goes in every
    lab in this module.
    """
    feedback_page = session.get(f"{base_url}/feedback")
    csrf = get_csrf_from_response(feedback_page.text)

    data = {
        "email": email,
        "name": name,
        "subject": subject,
        "message": message,
    }
    if csrf:
        data["csrf"] = csrf

    return session.post(f"{base_url}/feedback/submit", data=data)


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


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, content):
    """
    Print a clearly bordered block — used for showing leaked output,
    command results, or exploit payloads.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
