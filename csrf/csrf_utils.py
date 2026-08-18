# csrf_utils.py — shared utilities for CSRF lab automation scripts
#
# Mirrors sqli_utils.py and xss_utils.py in structure.
# Import in each lab script with:
#   from csrf_utils import banner, section, make_session, get_csrf, ...

import re
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          PortSwigger — CSRF Lab Automation Suite             ║
║          Cross-Site Request Forgery / Python + requests      ║
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
    certificate for its HTTPS interception proxy. Without verify=False,
    requests would reject Burp's certificate and the connection would fail.
    """
    s = requests.Session()
    s.verify = False
    if proxies:
        s.proxies = proxies
    return s


def login(session, base_url, username="wiener", password="peter"):
    """
    Log in to the PortSwigger lab with the provided credentials.

    Most CSRF labs use wiener:peter as the test account.
    Returns True on success, False on failure.

    Note: we fetch the login page first to get the CSRF token that the
    login form itself requires — PortSwigger protects the login endpoint
    with its own CSRF token.
    """
    login_page = session.get(f"{base_url}/login")
    csrf = get_csrf_from_response(login_page.text)
    if not csrf:
        print("  ✘  Could not find CSRF token on login page")
        return False

    data = {"csrf": csrf, "username": username, "password": password}
    r = session.post(f"{base_url}/login", data=data, allow_redirects=True)

    if "Log out" in r.text or "Your username is" in r.text:
        print(f"  ✔  Logged in as {username}")
        return True

    print(f"  ✘  Login failed (status {r.status_code})")
    return False


def get_csrf_from_response(html):
    """
    Extract a CSRF token from an HTML page's hidden form input.

    Looks for:  <input name="csrf" value="TOKEN">
    Returns the token string or None if not found.

    📝 CSRF tokens in PortSwigger labs are always in a hidden <input>
       with name="csrf". In real apps they might also appear in a
       <meta> tag or as a custom request header.
    """
    m = (re.search(r'<input[^>]+name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html) or
         re.search(r'name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html) or
         re.search(r'value=["\']([^"\']+)["\'][^>]+name=["\']csrf["\']', html))
    return m.group(1) if m else None


def get_account_page(session, base_url):
    """Fetch and return the /my-account page response."""
    return session.get(f"{base_url}/my-account")


def change_email(session, base_url, new_email, csrf_token=None):
    """
    Submit the email change form.

    If csrf_token is None, the form is sent without any csrf parameter
    (used for testing labs where the token is absent or optional).

    Returns the response object.
    """
    data = {"email": new_email}
    if csrf_token is not None:
        data["csrf"] = csrf_token
    return session.post(
        f"{base_url}/my-account/change-email",
        data=data,
        allow_redirects=True
    )


def check_email_changed(response_text, expected_email):
    """
    Check whether the email change was successful by looking for
    the new email address in the account page response.
    """
    if expected_email in response_text:
        print(f"  ✔  Email successfully changed to {expected_email}")
        return True
    print(f"  ✘  Email change not confirmed in response")
    return False


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, code):
    """
    Print a clearly bordered block containing an exploit payload.
    Used for labs requiring the exploit server or manual browser steps.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in code.strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")


def print_exploit_steps():
    """Print the standard exploit server delivery steps."""
    print("  ➜  Exploit server delivery steps:")
    print("     1. Go to the exploit server")
    print("     2. Paste the HTML above into the Body field")
    print("     3. Click 'Store'")
    print("     4. Click 'View exploit' to test on yourself first")
    print("     5. Click 'Deliver exploit to victim'")
